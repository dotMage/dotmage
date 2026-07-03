//! `dmage init <app>` — create app from a local secrets file (.env, xml, ...).

use dotmage_client::container::{self, FileMeta};
use dotmage_crypto::blob;
use dotmage_crypto::secret;

use super::{describe_payload, detect_format, empty_guard, file_basename, CliError, Context};

pub fn run(
    ctx: &mut Context,
    name: &str,
    file: Option<&str>,
    format_override: Option<&str>,
    allow_empty: bool,
) -> Result<(), CliError> {
    let ak = ctx.require_ak()?;
    let file = file.unwrap_or(container::DEFAULT_ENV_FILE);

    // Check the file exists
    let path = std::path::Path::new(file);
    if !path.exists() {
        return Err(CliError::Other(format!(
            "no {file} in current directory (use --file)"
        )));
    }

    // .gitignore guard — any secrets file, not just .env
    gitignore_guard(file)?;

    let data = std::fs::read(path)?;
    let base = file_basename(file);
    let format = match format_override {
        Some(f) => f.parse().map_err(CliError::Other)?,
        None => detect_format(&base, &data),
    };
    let meta = FileMeta {
        file_name: base,
        format,
    };

    empty_guard(file, &data, format, allow_empty)?;

    // Create app
    ctx.backend.create_app(name)?;

    // Create default env "dev"
    ctx.backend.create_env(name, &ctx.active_env, None)?;

    // Encrypt and push first revision
    let payload = container::encode(&meta, &data);
    let encrypted = secret::encrypt_secret(&ak, &payload, name, &ctx.active_env, 1)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let blob_str = blob::encode_blob(&encrypted);

    ctx.backend
        .push_revision(name, &ctx.active_env, &blob_str, 0)?;

    ctx.success(&format!(
        "Created app '\x1b[1m{name}\x1b[0m'. Pushed revision 1 from {file} ({}).{}",
        describe_payload(&meta, &data),
        ctx.server_suffix()
    ));
    Ok(())
}

/// Check if the secrets file is in .gitignore, warn if not (F.7).
fn gitignore_guard(env_file: &str) -> Result<(), CliError> {
    let gitignore = std::path::Path::new(".gitignore");
    if !gitignore.exists() {
        eprintln!("warning: {env_file} is not in .gitignore — risk of committing secrets.");
        return Ok(());
    }

    let content = std::fs::read_to_string(gitignore)?;
    let basename = std::path::Path::new(env_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(env_file);

    let covered = content.lines().any(|line| {
        let line = line.trim();
        line == env_file || line == basename || line == ".env" || line == ".env*"
    });

    if !covered {
        eprintln!(
            "warning: {env_file} is not in .gitignore — risk of committing secrets.\n\
             hint: add '{basename}' to .gitignore"
        );
    }
    Ok(())
}
