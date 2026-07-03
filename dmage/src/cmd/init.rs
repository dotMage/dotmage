//! `dmage init <app>` — create app from current .env.

use dotmage_crypto::blob;
use dotmage_crypto::secret;

use super::{count_env_keys, empty_guard, CliError, Context};

pub fn run(ctx: &mut Context, name: &str, file: &str, allow_empty: bool) -> Result<(), CliError> {
    let ak = ctx.require_ak()?;

    // Check .env exists
    let path = std::path::Path::new(file);
    if !path.exists() {
        return Err(CliError::Other(format!(
            "no {file} in current directory (use --file)"
        )));
    }

    // .gitignore guard
    gitignore_guard(file)?;

    let plaintext = std::fs::read(path)?;
    empty_guard(file, &plaintext, allow_empty)?;
    let key_count = count_env_keys(&plaintext);

    // Create app
    ctx.backend.create_app(name)?;

    // Create default env "dev"
    ctx.backend.create_env(name, &ctx.active_env, None)?;

    // Encrypt and push first revision
    let encrypted = secret::encrypt_secret(&ak, &plaintext, name, &ctx.active_env, 1)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let blob_str = blob::encode_blob(&encrypted);

    ctx.backend
        .push_revision(name, &ctx.active_env, &blob_str, 0)?;

    ctx.success(&format!(
        "Created app '\x1b[1m{name}\x1b[0m'. Pushed revision 1 from {file} ({key_count} keys)."
    ));
    Ok(())
}

/// Check if .env is in .gitignore, warn if not (F.7).
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
