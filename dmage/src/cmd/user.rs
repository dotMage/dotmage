//! `dmage user` — team management (spec K, team mode) and `dmage whoami`.

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use dotmage_client::backend_http::HttpBackend;
use dotmage_crypto::invite;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::{host_of, CliError, Context};

pub enum UserCmd {
    List,
    Invite {
        name: String,
        role: String,
        ttl: String,
    },
    Role {
        name: String,
        role: String,
    },
    Rm {
        name: String,
        yes: bool,
    },
}

fn http_backend(ctx: &Context) -> Result<&HttpBackend, CliError> {
    ctx.backend
        .as_any()
        .downcast_ref::<HttpBackend>()
        .ok_or_else(|| CliError::Other("team commands require a server connection".into()))
}

/// Team endpoints exist only on team-mode servers (spec B.9).
fn require_team_feature(backend: &HttpBackend) -> Result<(), CliError> {
    let health = backend.health()?;
    if health.features.iter().any(|f| f == "team") {
        return Ok(());
    }
    Err(CliError::Other(
        "this server runs in solo mode — set DOTMAGE_MODE=team on the server and restart\n         (old servers need an upgrade: dotmage-server with the 'team' feature)"
            .into(),
    ))
}

pub fn run(ctx: &mut Context, cmd: UserCmd) -> Result<(), CliError> {
    match cmd {
        UserCmd::List => list(ctx),
        UserCmd::Invite { name, role, ttl } => invite_user(ctx, &name, &role, &ttl),
        UserCmd::Role { name, role } => set_role(ctx, &name, &role),
        UserCmd::Rm { name, yes } => remove_user(ctx, &name, yes),
    }
}

fn find_user_id(backend: &HttpBackend, name: &str) -> Result<String, CliError> {
    let (users, _) = backend.users_list()?;
    users
        .iter()
        .find(|u| u.name == name && u.status == "active")
        .map(|u| u.id.clone())
        .ok_or_else(|| CliError::Other(format!("no active user '{name}' — see: dmage user list")))
}

fn set_role(ctx: &Context, name: &str, role: &str) -> Result<(), CliError> {
    if !matches!(role, "owner" | "editor" | "viewer") {
        return Err(CliError::Other(format!(
            "unknown role '{role}' (owner|editor|viewer)"
        )));
    }
    let backend = http_backend(ctx)?;
    require_team_feature(backend)?;
    let user_id = find_user_id(backend, name)?;
    backend.users_set_role(&user_id, role)?;
    ctx.success(&format!("'{name}' is now {role}"));
    Ok(())
}

/// Offboarding (spec K.5 / umbrella plan Phase 5): the safe path is the
/// default path — removal chains straight into a key rotation offer.
fn remove_user(ctx: &mut Context, name: &str, yes: bool) -> Result<(), CliError> {
    {
        let backend = http_backend(ctx)?;
        require_team_feature(backend)?;
        let user_id = find_user_id(backend, name)?;

        if !yes {
            eprintln!("  Removing '{name}': their wraps are deleted and devices revoked.");
            eprintln!("  Their CACHED key still decrypts data pushed before a rotation.");
            eprint!("  Remove? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                return Err(CliError::Other("aborted".into()));
            }
        }

        let revoked = backend.users_remove(&user_id)?;
        ctx.success(&format!("removed '{name}' ({revoked} device(s) revoked)"));
    }

    // Rotation is what actually locks them out of FUTURE data.
    if yes {
        ctx.print("IMPORTANT: run `dmage rotate-key` — their cached key still works until then");
        ctx.print("also rotate the secret VALUES they saw, and destroy pre-rotation backups");
        return Ok(());
    }
    eprint!("  Rotate the Account Key now (recommended)? [Y/n] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y") {
        super::rotate_key::run(ctx, true)?;
        ctx.print("also rotate the secret VALUES they saw, and destroy pre-rotation backups");
    } else {
        ctx.print("SKIPPED rotation — their cached key still decrypts everything until you run: dmage rotate-key");
    }
    Ok(())
}

pub fn whoami(ctx: &Context) -> Result<(), CliError> {
    let backend = http_backend(ctx)?;
    let me = backend.whoami()?;
    let server = ctx.config.server_url.as_deref().map(host_of);

    if ctx.json {
        println!("{}", whoami_json(&me, server));
        return Ok(());
    }

    println!("  user     {} ({})", me.name, me.role);
    println!("  device   {} ({})", me.device_name, me.device_id);
    if let Some(host) = server {
        println!("  server   {host}");
    }
    Ok(())
}

/// JSON contract (spec §5, semver) — fields spelled out, see apps.rs.
fn whoami_json(me: &dotmage_client::types::WhoamiInfo, server: Option<&str>) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "user": { "name": me.name, "role": me.role },
        "device": { "name": me.device_name, "id": me.device_id },
        "server": server,
    }))
    .expect("json object serializes")
}

fn list(ctx: &Context) -> Result<(), CliError> {
    let backend = http_backend(ctx)?;
    require_team_feature(backend)?;
    let (users, invitations) = backend.users_list()?;

    println!("  {:<14} {:<8} {:<9} SINCE", "USER", "ROLE", "STATUS");
    for u in &users {
        println!(
            "  {:<14} {:<8} {:<9} {}",
            u.name,
            u.role,
            u.status,
            &u.created_at[..u.created_at.len().min(10)]
        );
    }
    if !invitations.is_empty() {
        println!();
        println!("  {:<14} {:<8} {:<9} EXPIRES", "INVITED", "ROLE", "STATUS");
        for i in &invitations {
            println!(
                "  {:<14} {:<8} {:<9} {}",
                i.name,
                i.role,
                i.status,
                &i.expires_at[..i.expires_at.len().min(19)]
            );
        }
    }
    Ok(())
}

fn invite_user(ctx: &mut Context, name: &str, role: &str, ttl: &str) -> Result<(), CliError> {
    if !matches!(role, "owner" | "editor" | "viewer") {
        return Err(CliError::Other(format!(
            "unknown role '{role}' (owner|editor|viewer)"
        )));
    }

    let ak = ctx.require_ak()?;
    let backend = http_backend(ctx)?;
    require_team_feature(backend)?;

    // Seal AK with a key that exists only inside the token (spec K.1).
    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    rand::rngs::OsRng.fill_bytes(&mut r);
    let sealed = invite::seal_ak_invite(&k, &ak).map_err(|e| CliError::Crypto(e.to_string()))?;

    let redeem_secret = B64.encode(r);
    let redeem_hash = hex::encode(Sha256::digest(redeem_secret.as_bytes()));

    let (invitation_id, expires_at) = backend.users_invite(
        name,
        role,
        ttl,
        &B64.encode(&sealed.ciphertext),
        &B64.encode(sealed.nonce),
        &redeem_hash,
    )?;

    let server_url = ctx
        .config
        .server_url
        .clone()
        .ok_or_else(|| CliError::Other("no server url".into()))?;
    let payload = serde_json::json!({
        "v": 1,
        "i": invitation_id,
        "r": redeem_secret,
        "k": B64.encode(k),
        "s": server_url,
    });
    let token = format!(
        "dmage_uinv_{}",
        B64URL.encode(payload.to_string().as_bytes())
    );

    ctx.print(&format!(
        "Invitation for '{name}' ({role}) — expires {expires_at}"
    ));
    println!("\n  {token}\n");
    ctx.print("send this token over a PRIVATE channel — it can unlock the vault once");
    ctx.print(&format!(
        "on their machine: dmage auth --invite {}...",
        &token[..24.min(token.len())]
    ));
    Ok(())
}

/// Parsed invite token (K.1 wire format).
pub struct InviteToken {
    pub invitation_id: String,
    pub redeem_secret: String,
    pub k: [u8; 32],
    pub server_url: String,
}

pub fn parse_invite_token(token: &str) -> Result<InviteToken, CliError> {
    let blob = token
        .strip_prefix("dmage_uinv_")
        .ok_or_else(|| CliError::Other("not an invite token (expected dmage_uinv_...)".into()))?;
    let decoded = B64URL
        .decode(blob)
        .map_err(|e| CliError::Other(format!("invalid invite token: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| CliError::Other(format!("invalid invite token payload: {e}")))?;

    let field = |key: &str| -> Result<String, CliError> {
        payload[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| CliError::Other(format!("invite token missing '{key}'")))
    };

    let k_bytes = B64
        .decode(field("k")?)
        .map_err(|e| CliError::Other(format!("invalid key in invite token: {e}")))?;
    let k: [u8; 32] = k_bytes
        .try_into()
        .map_err(|_| CliError::Other("invite key must be 32 bytes".into()))?;

    Ok(InviteToken {
        invitation_id: field("i")?,
        redeem_secret: field("r")?,
        k,
        server_url: field("s")?,
    })
}
