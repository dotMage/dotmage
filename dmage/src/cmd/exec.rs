//! `dmage exec <app> -- <command>` — run with secrets in memory, no disk write.

use dotmage_client::container::FileFormat;
use dotmage_client::types::RevSpec;

use super::{CliError, Context};

pub fn run(ctx: &mut Context, name: &str, command: &[String]) -> Result<(), CliError> {
    if command.is_empty() {
        return Err(CliError::Other(
            "usage: dmage exec <app> <command...>\n         example: dmage exec myapp npm run dev"
                .into(),
        ));
    }

    let (_, decoded) = ctx.pull_decoded(name, &RevSpec::Latest)?;

    if decoded.meta.format != FileFormat::Env {
        return Err(CliError::Other(format!(
            "'{name}/{}' stores {} ({}) — exec only works with env format",
            ctx.active_env,
            decoded.meta.file_name,
            decoded.meta.format.as_str()
        )));
    }

    // Parse .env content into key-value pairs
    let env_vars = parse_env(&decoded.data);

    // Run the command with injected env vars
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(env_vars)
        .status()?;

    std::process::exit(status.code().unwrap_or(1));
}

fn parse_env(data: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, val) = line.split_once('=')?;
            let val = val.trim_matches('"').trim_matches('\'');
            Some((key.trim().to_string(), val.to_string()))
        })
        .collect()
}
