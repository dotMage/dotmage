//! `dmage auth` — authenticate, cache AK in keychain.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use dotmage_client::backend_http::HttpBackend;
use dotmage_client::keychain;
use dotmage_client::token::{self, ServerTokens};
use dotmage_client::types::*;
use dotmage_crypto::envelope;
use dotmage_crypto::kdf;

use super::{CliError, Context};

/// `dmage auth --invite` — join a team (spec K.2): redeem, unseal AK, pick a
/// password, upload the personal wrap, register this device.
pub fn join_with_invite(
    ctx: &mut Context,
    token_str: &str,
    ttl: Option<String>,
) -> Result<(), CliError> {
    let ttl_secs = parse_ttl(ttl.as_deref()).unwrap_or(ctx.config.key_ttl_secs);
    let token = super::user::parse_invite_token(token_str)?;

    let backend = ctx
        .backend
        .as_any()
        .downcast_ref::<HttpBackend>()
        .ok_or_else(|| CliError::Other("joining requires server mode".into()))?;

    // Step 1: sealed AK
    let resp = backend.invite_redeem(&token.invitation_id, &token.redeem_secret)?;
    let nonce: [u8; 24] = B64
        .decode(&resp.nonce_inv)
        .map_err(|e| CliError::Crypto(e.to_string()))?
        .try_into()
        .map_err(|_| CliError::Crypto("invalid invitation nonce".into()))?;
    let sealed = dotmage_crypto::envelope::WrappedAk {
        nonce,
        ciphertext: B64
            .decode(&resp.sealed_ak)
            .map_err(|e| CliError::Crypto(e.to_string()))?,
    };
    let ak = dotmage_crypto::invite::unseal_ak_invite(&token.k, &sealed)
        .map_err(|_| CliError::Other("cannot unseal invitation — token corrupted?".into()))?;

    println!(
        "\n  \x1b[36mJoining as '{}' ({}) — pick YOUR OWN master password\x1b[0m\n",
        resp.name, resp.role
    );
    let password = prompt_password("New master password: ")?;
    let confirm = prompt_password("Confirm master password: ")?;
    if password != confirm {
        return Err(CliError::Other("passwords do not match".into()));
    }

    // Personal wrap (spec K.0): own salt, own MK, shared AK.
    let salt = kdf::generate_salt();
    let mk = kdf::derive_master_key(password.as_bytes(), &salt)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let wrapped = envelope::wrap_ak(&mk, &ak).map_err(|e| CliError::Crypto(e.to_string()))?;

    // Step 2: create user + device
    let joined = backend.invite_complete(
        &token.invitation_id,
        &token.redeem_secret,
        &hostname(),
        &B64.encode(salt),
        &ArgonParamsDto {
            memory: kdf::ARGON2_MEMORY_KIB,
            iterations: kdf::ARGON2_ITERATIONS,
            parallelism: kdf::ARGON2_PARALLELISM,
            version: kdf::ARGON2_VERSION,
        },
        &B64.encode(wrapped.nonce),
        &B64.encode(&wrapped.ciphertext),
    )?;

    save_device_tokens(
        ctx,
        &dotmage_client::backend_http::DeviceAuthResp {
            device_token: joined.device_token,
            refresh_token: joined.refresh_token,
            device_id: joined.account_id,
            token_expires_at: joined.expires_at,
        },
    )?;
    ctx.refresh_backend()?;

    let server_hash = keychain::server_hash(&ctx.config.server_id());
    keychain::store_ak_gen(&server_hash, &ak, resp.key_gen, ttl_secs)
        .map_err(|e| CliError::Keychain(e.to_string()))?;

    ctx.success(&format!(
        "Joined as '{}' ({}). Key cached.",
        resp.name, resp.role
    ));
    ctx.print("your password is yours alone — nobody else on the team knows it");
    Ok(())
}

pub fn run(ctx: &mut Context, ttl: Option<String>, enroll: Option<String>) -> Result<(), CliError> {
    let ttl_secs = parse_ttl(ttl.as_deref()).unwrap_or(ctx.config.key_ttl_secs);

    let account_exists = ctx.backend.account_exists()?;

    if !account_exists {
        return bootstrap(ctx, ttl_secs);
    }

    // Account exists — register or unlock this device
    if let Some(enroll_token) = enroll {
        return enroll_with_token(ctx, &enroll_token, ttl_secs);
    }

    // Check if we already have a valid token (returning device)
    let server_hash = keychain::server_hash(&ctx.config.server_id());
    let has_tokens = token::load_tokens(&server_hash).ok().flatten().is_some();

    if has_tokens {
        // Existing device, just re-enter password to cache AK
        return unlock_existing(ctx, ttl_secs);
    }

    // New device, no enrollment token → register with bootstrap secret
    register_with_bootstrap(ctx, ttl_secs)
}

/// Enroll a device using an enrollment token (CI/programmatic).
fn enroll_with_token(ctx: &mut Context, enroll_token: &str, ttl_secs: u64) -> Result<(), CliError> {
    let backend = ctx
        .backend
        .as_any()
        .downcast_ref::<HttpBackend>()
        .ok_or_else(|| CliError::Other("enroll requires server mode".into()))?;

    let device_name = hostname();
    let resp = backend.register_with_enroll_token(enroll_token, &device_name)?;
    save_device_tokens(ctx, &resp)?;
    ctx.refresh_backend()?;

    unlock_ak(ctx, ttl_secs)?;
    ctx.success("Device enrolled. Key cached.");
    Ok(())
}

/// Register a new device using the bootstrap secret (interactive).
fn register_with_bootstrap(ctx: &mut Context, ttl_secs: u64) -> Result<(), CliError> {
    println!("\n  \x1b[36mNew device — register with bootstrap secret\x1b[0m\n");

    let backend = ctx
        .backend
        .as_any()
        .downcast_ref::<HttpBackend>()
        .ok_or_else(|| CliError::Other("requires server mode".into()))?;

    let bootstrap_secret = prompt_password("Bootstrap secret: ")?;
    let device_name = hostname();
    let resp = backend.register_with_bootstrap(&bootstrap_secret, &device_name)?;
    save_device_tokens(ctx, &resp)?;
    ctx.refresh_backend()?;

    unlock_ak(ctx, ttl_secs)?;

    let days = ttl_secs / 86400;
    ctx.success(&format!(
        "Device registered. Key cached (expires in {days}d)."
    ));
    Ok(())
}

/// Existing device with tokens — just unlock AK with password.
fn unlock_existing(ctx: &mut Context, ttl_secs: u64) -> Result<(), CliError> {
    unlock_ak(ctx, ttl_secs)?;
    let days = ttl_secs / 86400;
    ctx.success(&format!("Authenticated. Key cached (expires in {days}d)."));
    Ok(())
}

/// Fetch account keys, prompt password, derive MK, unwrap AK, store in keychain.
fn unlock_ak(ctx: &mut Context, ttl_secs: u64) -> Result<(), CliError> {
    let keys = ctx.backend.get_account_keys()?;
    let password = prompt_password("Master password: ")?;

    let salt = B64
        .decode(&keys.salt)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let salt: [u8; 16] = salt
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

    let nonce_ak = B64
        .decode(&keys.nonce_ak)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let nonce_ak: [u8; 24] = nonce_ak
        .try_into()
        .map_err(|_| CliError::Crypto("invalid nonce".into()))?;
    let wrapped_ct = B64
        .decode(&keys.wrapped_ak)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let wrapped = envelope::WrappedAk {
        nonce: nonce_ak,
        ciphertext: wrapped_ct,
    };

    let ak = envelope::unwrap_ak(&mk, &wrapped)
        .map_err(|_| CliError::Other("invalid password".into()))?;

    let server_hash = keychain::server_hash(&ctx.config.server_id());
    keychain::store_ak_gen(&server_hash, &ak, keys.key_gen, ttl_secs)
        .map_err(|e| CliError::Keychain(e.to_string()))?;

    Ok(())
}

/// Save device tokens returned from enrollment/registration to disk.
fn save_device_tokens(
    ctx: &Context,
    resp: &dotmage_client::backend_http::DeviceAuthResp,
) -> Result<(), CliError> {
    let server_hash = keychain::server_hash(&ctx.config.server_id());
    token::save_tokens(
        &server_hash,
        &ServerTokens {
            device_token: resp.device_token.clone(),
            refresh_token: resp.refresh_token.clone(),
            device_id: resp.device_id.clone(),
        },
    )
    .map_err(|e| CliError::Other(e.to_string()))
}

fn bootstrap(ctx: &mut Context, ttl_secs: u64) -> Result<(), CliError> {
    println!("\n  \x1b[36mNo account found — creating new account\x1b[0m\n");

    let password = prompt_password("New master password: ")?;
    let password_confirm = prompt_password("Confirm master password: ")?;
    if password != password_confirm {
        return Err(CliError::Other("passwords do not match".into()));
    }

    // Ask for bootstrap secret if using server
    let bootstrap_secret = if ctx.server.is_some() {
        prompt_password("Bootstrap secret: ")?
    } else {
        String::new()
    };

    // Generate crypto material locally
    let salt = kdf::generate_salt();
    let mk = kdf::derive_master_key(password.as_bytes(), &salt)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let ak = envelope::generate_account_key();
    let wrapped = envelope::wrap_ak(&mk, &ak).map_err(|e| CliError::Crypto(e.to_string()))?;

    let device_name = hostname();

    let req = AccountInitReq {
        salt: B64.encode(salt),
        argon_params: ArgonParamsDto {
            memory: kdf::ARGON2_MEMORY_KIB,
            iterations: kdf::ARGON2_ITERATIONS,
            parallelism: kdf::ARGON2_PARALLELISM,
            version: kdf::ARGON2_VERSION,
        },
        nonce_ak: B64.encode(wrapped.nonce),
        wrapped_ak: B64.encode(&wrapped.ciphertext),
        device_name: device_name.clone(),
        bootstrap_secret,
        salt_rc: None,
        nonce_rc: None,
        wrapped_ak_rc: None,
    };

    let resp = ctx.backend.account_init(&req)?;

    // Store tokens
    let server_hash = keychain::server_hash(&ctx.config.server_id());
    token::save_tokens(
        &server_hash,
        &ServerTokens {
            device_token: resp.device_token,
            refresh_token: resp.refresh_token,
            device_id: resp.account_id,
        },
    )
    .map_err(|e: token::TokenError| CliError::Other(e.to_string()))?;

    // Store AK in keychain
    keychain::store_ak(&server_hash, &ak, ttl_secs)
        .map_err(|e| CliError::Keychain(e.to_string()))?;

    let days = ttl_secs / 86400;
    ctx.success(&format!(
        "Account created. Key cached (expires in {days}d)."
    ));
    Ok(())
}

pub(crate) fn prompt_password(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(prompt).map_err(CliError::Io)
}

fn parse_ttl(s: Option<&str>) -> Option<u64> {
    let s = s?;
    let s = s.trim();
    if let Some(days) = s.strip_suffix('d') {
        days.parse::<u64>().ok().map(|d| d * 86400)
    } else if let Some(hours) = s.strip_suffix('h') {
        hours.parse::<u64>().ok().map(|h| h * 3600)
    } else {
        s.parse::<u64>().ok()
    }
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        if let Ok(name) = unix_hostname() {
            return name;
        }
    }
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(unix)]
fn unix_hostname() -> Result<String, ()> {
    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) == 0 {
            if let Ok(s) = std::ffi::CStr::from_ptr(buf.as_ptr() as *const _).to_str() {
                return Ok(s.to_string());
            }
        }
    }
    Err(())
}
