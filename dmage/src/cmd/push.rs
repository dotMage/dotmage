//! `dmage push <app>` — encrypt a local secrets file → new revision.

use dotmage_client::container::{self, Decoded, FileMeta};
use dotmage_client::types::RevSpec;
use dotmage_crypto::blob;
use dotmage_crypto::secret;

use super::{describe_payload, detect_format, empty_guard, file_basename, CliError, Context};

pub fn run(
    ctx: &mut Context,
    name: &str,
    file_arg: Option<&str>,
    allow_empty: bool,
) -> Result<(), CliError> {
    let ak = ctx.require_ak()?;
    let env_name = ctx.active_env.clone();

    // Latest revision first: it carries the stored file name/format, and doubles
    // as the identical-content check below.
    let envs = ctx.backend.list_envs(name)?;
    let env_info = envs.iter().find(|e| e.name == env_name);
    let parent_rev = env_info.map(|e| e.latest_rev).unwrap_or(0);

    let prev: Option<Decoded> = if parent_rev > 0 {
        ctx.pull_decoded(name, &RevSpec::Latest)
            .ok()
            .map(|(_, d)| d)
    } else {
        None
    };

    // File to push: explicit --file, else the name stored in the manifest.
    let stored_name = prev.as_ref().map(|d| d.meta.file_name.clone());
    let file = file_arg
        .map(str::to_string)
        .or(stored_name)
        .unwrap_or_else(|| container::DEFAULT_ENV_FILE.into());

    let path = std::path::Path::new(&file);
    if !path.exists() {
        return Err(CliError::Other(format!("no {file} found")));
    }
    let data = std::fs::read(path)?;

    let base = file_basename(&file);
    // The stored format wins; detection only warns on mismatch.
    let detected = detect_format(&base, &data);
    let format = match prev.as_ref() {
        Some(d) => {
            if d.meta.format != detected {
                eprintln!(
                    "warning: {file} looks like {}, but this env stores {} — keeping {}",
                    detected.as_str(),
                    d.meta.format.as_str(),
                    d.meta.format.as_str()
                );
            }
            d.meta.format
        }
        None => detected,
    };
    let meta = FileMeta {
        file_name: base,
        format,
    };

    // Empty guard runs before the prod-guard prompt: don't ask the user to
    // confirm a push that would fail anyway.
    empty_guard(&file, &data, format, allow_empty)?;

    // Prod-guard
    if ctx.config.is_protected_env(&env_name) {
        eprint!("This will push to PROTECTED env '{env_name}'. Type '{env_name}' to confirm: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != env_name {
            return Err(CliError::Other("aborted".into()));
        }
    }

    // Identical-content check compares the inner payloads, so a metadata-only
    // rewrite never creates a revision.
    if let Some(ref d) = prev {
        if d.data == data {
            ctx.print(&format!("nothing to push (identical to rev {parent_rev})"));
            return Ok(());
        }
    }

    let new_rev = parent_rev + 1;
    let payload = container::encode(&meta, &data);
    let encrypted = secret::encrypt_secret(&ak, &payload, name, &env_name, new_rev)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let blob_str = blob::encode_blob(&encrypted);

    let pushed = ctx
        .backend
        .push_revision(name, &env_name, &blob_str, parent_rev)?;

    ctx.success(&format!(
        "Pushed revision {} ({}).{}",
        pushed.rev_number,
        describe_payload(&meta, &data),
        ctx.server_suffix()
    ));
    Ok(())
}
