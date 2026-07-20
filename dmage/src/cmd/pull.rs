//! `dmage pull <app>` — download, decrypt, write the stored secrets file.

use dotmage_client::types::RevSpec;

use super::{describe_payload, CliError, Context};

pub fn run(
    ctx: &mut Context,
    name: &str,
    rev: Option<&str>,
    output: Option<&str>,
    to_stdout: bool,
    force: bool,
) -> Result<(), CliError> {
    let rev_spec = match rev {
        Some("last") | None => RevSpec::Latest,
        Some(n) => RevSpec::Number(
            n.parse::<u64>()
                .map_err(|_| CliError::Other(format!("invalid revision: {n}")))?,
        ),
    };

    let (rev_number, decoded) = ctx.pull_decoded(name, &rev_spec)?;

    if to_stdout {
        use std::io::Write;
        std::io::stdout().write_all(&decoded.data)?;
        return Ok(());
    }

    // Output file: explicit --output, else the name stored in the manifest.
    let out_path = output.unwrap_or(&decoded.meta.file_name);
    let path = std::path::Path::new(out_path);

    // Confirm overwrite if file exists and differs
    if path.exists() && !force {
        let existing = std::fs::read(path)?;
        if existing != decoded.data {
            eprint!("{out_path} differs from rev {rev_number}. Overwrite? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                return Err(CliError::Other("aborted".into()));
            }
        }
    }

    std::fs::write(path, &decoded.data)?;
    ctx.record_sync_state(name, &ctx.active_env.clone(), rev_number, out_path, &decoded.data);

    ctx.success(&format!(
        "Wrote {out_path} from revision {rev_number} ({}).{}",
        describe_payload(&decoded.meta, &decoded.data),
        ctx.server_suffix()
    ));
    Ok(())
}
