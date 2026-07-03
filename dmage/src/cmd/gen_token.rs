//! `dmage gen-token` — generate enrollment token for adding a new device.

use dotmage_client::backend_http::HttpBackend;

use super::{CliError, Context};

pub fn run(ctx: &Context, name: Option<&str>, ttl: &str) -> Result<(), CliError> {
    let backend = ctx
        .backend
        .as_any()
        .downcast_ref::<HttpBackend>()
        .ok_or_else(|| {
            CliError::Other(
                "gen-token requires a server connection (run: dmage auth --server <url>)".into(),
            )
        })?;

    let device_name = name.unwrap_or("new-device");
    let (token, expires_at) = backend.gen_enroll_token(device_name, ttl)?;

    ctx.print("Token (copy now, shown once):");
    println!("  {token}");
    ctx.print(&format!("Expires: {expires_at}"));
    ctx.print(&format!(
        "\nOn the new device run:\n  dmage auth --server {} --enroll {token}",
        ctx.config.server_url.as_deref().unwrap_or("YOUR_SERVER")
    ));
    Ok(())
}
