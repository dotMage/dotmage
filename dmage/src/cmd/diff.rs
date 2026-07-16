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

    if ctx.json {
        // The JSON contract never carries secret values — --show-values is a
        // local human affordance; JSON output ends up in CI logs.
        println!(
            "{}",
            render_json(local_file, rev_number, remote.meta.format, &local_data, &remote.data)
        );
        return Ok(());
    }

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

/// JSON contract (spec §5, semver): env diffs list keys and change kinds — no
/// values, ever. Non-env formats report sizes and equality only.
fn render_json(
    file: &str,
    rev: u64,
    format: FileFormat,
    local_data: &[u8],
    remote_data: &[u8],
) -> String {
    let base = |identical: bool| {
        serde_json::json!({
            "file": file,
            "rev": rev,
            "format": format.as_str(),
            "identical": identical,
        })
    };
    let doc = match format {
        FileFormat::Env => {
            let local_vars = parse_env_map(local_data);
            let remote_vars = parse_env_map(remote_data);
            let all_keys: BTreeSet<&str> = local_vars
                .keys()
                .chain(remote_vars.keys())
                .map(|s| s.as_str())
                .collect();
            let changes: Vec<serde_json::Value> = all_keys
                .into_iter()
                .filter_map(|key| {
                    let status = match (local_vars.get(key), remote_vars.get(key)) {
                        (Some(l), Some(r)) if l != r => "changed",
                        (Some(_), None) => "local_only",
                        (None, Some(_)) => "remote_only",
                        _ => return None,
                    };
                    Some(serde_json::json!({ "key": key, "status": status }))
                })
                .collect();
            let mut doc = base(changes.is_empty());
            doc["changes"] = serde_json::Value::Array(changes);
            doc
        }
        FileFormat::Text | FileFormat::Binary => {
            let identical = Sha256::digest(local_data) == Sha256::digest(remote_data);
            let mut doc = base(identical);
            doc["local_bytes"] = local_data.len().into();
            doc["remote_bytes"] = remote_data.len().into();
            doc
        }
    };
    serde_json::to_string_pretty(&doc).expect("json object serializes")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_diff_lists_keys_but_never_values() {
        let out = render_json(
            ".env",
            7,
            FileFormat::Env,
            b"SAME=1\nCHANGED=local-secret\nLOCAL_ONLY=x\n",
            b"SAME=1\nCHANGED=remote-secret\nREMOTE_ONLY=y\n",
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["identical"], false);
        let changes = v["changes"].as_array().unwrap();
        assert_eq!(changes.len(), 3);
        assert!(changes.iter().any(|c| c["key"] == "CHANGED" && c["status"] == "changed"));
        assert!(changes.iter().any(|c| c["key"] == "LOCAL_ONLY" && c["status"] == "local_only"));
        assert!(changes.iter().any(|c| c["key"] == "REMOTE_ONLY" && c["status"] == "remote_only"));
        // The contract: values must not appear anywhere in the document.
        assert!(!out.contains("local-secret"));
        assert!(!out.contains("remote-secret"));
    }

    #[test]
    fn identical_env_has_empty_changes() {
        let out = render_json(".env", 1, FileFormat::Env, b"A=1\n", b"A=1\n");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["identical"], true);
        assert_eq!(v["changes"], serde_json::json!([]));
    }

    #[test]
    fn binary_reports_sizes_only() {
        let out = render_json("cert.p12", 2, FileFormat::Binary, b"aaa", b"bbbb");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["identical"], false);
        assert_eq!(v["local_bytes"], 3);
        assert_eq!(v["remote_bytes"], 4);
        assert!(v.get("changes").is_none());
    }
}
