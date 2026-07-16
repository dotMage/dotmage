//! `dmage rotate-key` — re-encrypt every revision with a fresh Account Key (spec L).
//!
//! Client-driven: the server cannot read blobs, so it cannot re-encrypt them.
//! Resumable: interrupt at any point and re-run; state lives on the backend.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dotmage_client::keychain;
use dotmage_client::types::{RevSpec, RotateBeginReq};
use dotmage_crypto::{blob, envelope, kdf, secret};

use super::{auth::prompt_password, CliError, Context};

pub fn run(ctx: &mut Context, yes: bool) -> Result<(), CliError> {
    // The password gates the operation AND lets a resume re-derive both wraps.
    let keys = ctx.backend.get_account_keys()?;

    let status = ctx.backend.rotate_status()?;
    let resuming = status.in_progress;

    if !resuming && !yes {
        eprintln!("  This re-encrypts EVERY revision with a fresh key. Old cached keys,");
        eprintln!("  old backups and existing CI tokens will no longer decrypt new data.");
        eprint!("  Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            return Err(CliError::Other("aborted".into()));
        }
    }

    let password = prompt_password("Master password: ")?;
    let salt: [u8; 16] = B64
        .decode(&keys.salt)
        .map_err(|e| CliError::Crypto(e.to_string()))?
        .try_into()
        .map_err(|_| CliError::Crypto("invalid salt".into()))?;
    let params = kdf::ArgonParams {
        memory: keys.argon_params.memory,
        iterations: keys.argon_params.iterations,
        parallelism: keys.argon_params.parallelism,
        version: keys.argon_params.version,
    };
    let mk = kdf::derive_master_key_with_params(password.as_bytes(), &salt, &params)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let old_ak = unwrap(&mk, &keys.nonce_ak, &keys.wrapped_ak)
        .map_err(|_| CliError::Other("invalid password".into()))?;
    let old_gen = keys.key_gen;

    // Resolve AK′: unwrap the pending wrap when resuming, mint a fresh key otherwise.
    let (new_ak, new_gen) = if resuming {
        let nonce = status
            .pending_nonce_ak
            .clone()
            .ok_or_else(|| CliError::Other("rotation state missing pending wrap".into()))?;
        let wrapped = status
            .pending_wrapped_ak
            .clone()
            .ok_or_else(|| CliError::Other("rotation state missing pending wrap".into()))?;
        let ak = unwrap(&mk, &nonce, &wrapped)
            .map_err(|_| CliError::Other("cannot unwrap pending key — wrong password?".into()))?;
        let gen = status
            .new_key_gen
            .ok_or_else(|| CliError::Other("rotation state missing new_key_gen".into()))?;
        ctx.print(&format!("resuming rotation to generation {gen}"));
        (ak, gen)
    } else {
        let ak = *envelope::generate_account_key();
        let wrapped = envelope::wrap_ak(&mk, &ak).map_err(|e| CliError::Crypto(e.to_string()))?;
        let new_gen = old_gen + 1;
        ctx.backend.rotate_begin(&RotateBeginReq {
            new_key_gen: new_gen,
            nonce_ak: B64.encode(wrapped.nonce),
            wrapped_ak: B64.encode(&wrapped.ciphertext),
            salt_rc: None,
            nonce_rc: None,
            wrapped_ak_rc: None,
        })?;
        (ak, new_gen)
    };

    // Walk stale revisions in pages until none remain.
    let mut done = 0u64;
    let mut skipped: Vec<String> = Vec::new();
    loop {
        let status = ctx.backend.rotate_status()?;
        if status.stale.is_empty() {
            break;
        }
        let total = done + status.stale_count;
        for item in &status.stale {
            let revision = ctx.backend.pull_revision(
                &item.app,
                &item.env,
                &RevSpec::Number(item.rev_number),
            )?;
            if revision.key_gen >= new_gen {
                continue; // already swapped by an interrupted run
            }
            // A revision that fails to decode or decrypt was already unreadable
            // before this rotation (e.g. corrupted server-side). Re-encrypting
            // it is impossible, but one broken revision must not block the
            // security-critical rotation of everything else: keep its bytes
            // verbatim, mark it with the new generation, and report loudly.
            let reencrypted = blob::decode_blob(&revision.blob)
                .map_err(|e| e.to_string())
                .and_then(|decoded| {
                    secret::decrypt_secret(
                        &old_ak,
                        &decoded,
                        &item.app,
                        &item.env,
                        item.rev_number,
                    )
                    .map_err(|e| e.to_string())
                });
            let blob_out = match reencrypted {
                Ok(plaintext) => {
                    let encrypted = secret::encrypt_secret(
                        &new_ak,
                        &plaintext,
                        &item.app,
                        &item.env,
                        item.rev_number,
                    )
                    .map_err(|e| CliError::Crypto(e.to_string()))?;
                    blob::encode_blob(&encrypted)
                }
                Err(e) => {
                    let id = format!("{}/{} rev {}", item.app, item.env, item.rev_number);
                    eprintln!(
                        "  \x1b[31m!\x1b[0m {id}: cannot re-encrypt ({e}) — revision was \
                         already unreadable; keeping its bytes as-is and continuing"
                    );
                    skipped.push(id);
                    revision.blob.clone()
                }
            };
            ctx.backend.rotate_put_blob(
                &item.app,
                &item.env,
                item.rev_number,
                &blob_out,
                new_gen,
            )?;
            done += 1;
            if done.is_multiple_of(10) || done == total {
                ctx.print(&format!("re-encrypted {done}/{total} revisions"));
            }
        }
    }

    let current = ctx.backend.rotate_complete()?;

    if !skipped.is_empty() {
        eprintln!(
            "  \x1b[31m!\x1b[0m {} revision(s) could not be re-encrypted and remain unreadable:",
            skipped.len()
        );
        for id in &skipped {
            eprintln!("      {id}");
        }
        eprintln!(
            "      They were unreadable before the rotation too. If a revision matters,\n      \
             restore it from a pre-rotation backup and push it as a new revision."
        );
    }

    // The rotator's cache moves to the new generation immediately.
    let server_hash = keychain::server_hash(&ctx.config.server_id());
    keychain::store_ak_gen(&server_hash, &new_ak, current, ctx.config.key_ttl_secs)
        .map_err(|e| CliError::Keychain(e.to_string()))?;

    ctx.success(&format!(
        "Key rotated to generation {current} ({done} revision(s) re-encrypted).{}",
        ctx.server_suffix()
    ));
    ctx.print("old cached keys and pre-rotation backups no longer match new data");
    ctx.print("if you use CI tokens, regenerate them: dmage gen-ci-token (they embed the old key)");
    ctx.print("other devices must re-run: dmage auth");
    Ok(())
}

fn unwrap(mk: &kdf::MasterKey, nonce_b64: &str, wrapped_b64: &str) -> Result<[u8; 32], ()> {
    let nonce: [u8; 24] = B64
        .decode(nonce_b64)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())?;
    let ciphertext = B64.decode(wrapped_b64).map_err(|_| ())?;
    envelope::unwrap_ak(mk, &envelope::WrappedAk { nonce, ciphertext })
        .map(|z| *z)
        .map_err(|_| ())
}
