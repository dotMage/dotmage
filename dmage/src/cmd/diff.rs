//! `dmage diff <app>` — compare the local secrets file with remote.

use dotmage_client::container::FileFormat;
use dotmage_client::types::RevSpec;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use super::{human_size, CliError, Context};

pub fn run(
    ctx: &mut Context,
    name: &str,
    show_values: bool,
    file_arg: Option<&str>,
) -> Result<(), CliError> {
    // Remote first: its manifest tells us which local file to compare against.
    let (rev_number, remote) = ctx.pull_decoded(name, &RevSpec::Latest)?;

    let local_file = file_arg.unwrap_or(&remote.meta.file_name);
    let local_path = std::path::Path::new(local_file);
    if !local_path.exists() {
        return Err(CliError::Other(format!("no local {local_file} file")));
    }
    let local_data = std::fs::read(local_path)?;

    match remote.meta.format {
        FileFormat::Env => diff_env(
            local_file,
            &local_data,
            &remote.data,
            rev_number,
            show_values,
        ),
        FileFormat::Text => {
            println!(
                "Comparing ./{local_file} <> rev {rev_number} ({}):",
                remote.meta.format.as_str()
            );
            if local_data == remote.data {
                println!("  (identical)");
            } else {
                println!(
                    "  ~ contents differ: local {} lines ({}), remote {} lines ({})",
                    count_lines(&local_data),
                    human_size(local_data.len()),
                    count_lines(&remote.data),
                    human_size(remote.data.len())
                );
            }
            Ok(())
        }
        FileFormat::Binary => {
            println!(
                "Comparing ./{local_file} <> rev {rev_number} ({}):",
                remote.meta.format.as_str()
            );
            if Sha256::digest(&local_data) == Sha256::digest(&remote.data) {
                println!("  (identical)");
            } else {
                println!(
                    "  ~ contents differ: local {}, remote {}",
                    human_size(local_data.len()),
                    human_size(remote.data.len())
                );
            }
            Ok(())
        }
    }
}

fn count_lines(data: &[u8]) -> usize {
    String::from_utf8_lossy(data).lines().count()
}

fn diff_env(
    local_file: &str,
    local_data: &[u8],
    remote_data: &[u8],
    rev_number: u64,
    show_values: bool,
) -> Result<(), CliError> {
    let local_vars = parse_env_map(local_data);
    let remote_vars = parse_env_map(remote_data);

    println!("Comparing ./{local_file} <> rev {rev_number}:");

    let all_keys: BTreeSet<&str> = local_vars
        .keys()
        .chain(remote_vars.keys())
        .map(|s| s.as_str())
        .collect();

    let mut changes = 0;
    for key in all_keys {
        let local_val = local_vars.get(key);
        let remote_val = remote_vars.get(key);

        match (local_val, remote_val) {
            (Some(l), Some(r)) if l != r => {
                if show_values {
                    println!("  ~ {key}  local={l}  remote={r}");
                } else {
                    println!("  ~ {key}   (changed)");
                }
                changes += 1;
            }
            (Some(_), None) => {
                println!("  + {key}   (local only)");
                changes += 1;
            }
            (None, Some(_)) => {
                println!("  - {key}   (remote only)");
                changes += 1;
            }
            _ => {} // identical
        }
    }

    if changes == 0 {
        println!("  (identical)");
    } else if !show_values {
        println!("(values hidden; use --show-values to reveal locally)");
    }

    Ok(())
}

fn parse_env_map(data: &[u8]) -> std::collections::BTreeMap<String, String> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, val) = line.split_once('=')?;
            Some((
                key.trim().to_string(),
                val.trim_matches('"').trim_matches('\'').to_string(),
            ))
        })
        .collect()
}
