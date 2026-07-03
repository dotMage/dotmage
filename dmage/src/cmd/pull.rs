//! `dmage pull <app>` — download, decrypt, write .env.

use dotmage_client::types::RevSpec;
use dotmage_crypto::blob;
use dotmage_crypto::secret;

use super::{count_env_keys, CliError, Context};

pub fn run(
    ctx: &mut Context,
    name: &str,
    rev: Option<&str>,
    output: Option<&str>,
    to_stdout: bool,
    force: bool,
) -> Result<(), CliError> {
    let ak = ctx.require_ak()?;
    let env_name = ctx.active_env.clone();

    let rev_spec = match rev {
        Some("last") | None => RevSpec::Latest,
        Some(n) => RevSpec::Number(
            n.parse::<u64>()
                .map_err(|_| CliError::Other(format!("invalid revision: {n}")))?,
        ),
    };

    let revision = ctx.backend.pull_revision(name, &env_name, &rev_spec)?;

    let decoded = blob::decode_blob(&revision.blob).map_err(|e| CliError::Crypto(e.to_string()))?;

    let plaintext = secret::decrypt_secret(&ak, &decoded, name, &env_name, revision.rev_number)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    if to_stdout {
        print!("{}", String::from_utf8_lossy(&plaintext));
        return Ok(());
    }

    let out_path = output.unwrap_or(".env");
    let path = std::path::Path::new(out_path);

    // Confirm overwrite if file exists and differs
    if path.exists() && !force {
        let existing = std::fs::read(path)?;
        if existing != plaintext {
            eprint!(
                "{out_path} differs from rev {}. Overwrite? [y/N] ",
                revision.rev_number
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                return Err(CliError::Other("aborted".into()));
            }
        }
    }

    std::fs::write(path, &plaintext)?;

    let key_count = count_env_keys(&plaintext);
    ctx.success(&format!(
        "Wrote {out_path} from revision {} ({key_count} keys).{}",
        revision.rev_number,
        ctx.server_suffix()
    ));
    Ok(())
}
