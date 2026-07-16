//! `dmage history <app>` — show revision history.

use dotmage_client::types::RevisionMeta;

use super::{CliError, Context};

pub fn run(ctx: &Context, name: &str) -> Result<(), CliError> {
    let revs = ctx.backend.list_revisions(name, &ctx.active_env)?;

    if ctx.json {
        println!("{}", render_json(&revs));
        return Ok(());
    }

    if revs.is_empty() {
        ctx.print("no revisions");
        return Ok(());
    }

    println!("{:<5} {:<22} {:<12} NOTE", "REV", "WHEN", "DEVICE");
    for rev in &revs {
        let when = &rev.created_at[..std::cmp::min(19, rev.created_at.len())];
        let note = rev
            .rollback_of
            .map(|r| format!("rollback of {r}"))
            .unwrap_or_default();
        println!(
            "{:<5} {:<22} {:<12} {}",
            rev.rev_number, when, rev.device_id, note
        );
    }
    Ok(())
}

/// JSON contract (spec §5, semver) — fields spelled out, see apps.rs.
fn render_json(revs: &[RevisionMeta]) -> String {
    let items: Vec<serde_json::Value> = revs
        .iter()
        .map(|r| {
            serde_json::json!({
                "rev_number": r.rev_number,
                "created_at": r.created_at,
                "device_id": r.device_id,
                "rollback_of": r.rollback_of,
                "content_hash": r.content_hash,
            })
        })
        .collect();
    serde_json::to_string_pretty(&items).expect("json array serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_fields_with_nulls() {
        let revs = vec![RevisionMeta {
            rev_number: 3,
            content_hash: None,
            created_at: "2026-07-16T10:00:00Z".into(),
            device_id: "dev-1".into(),
            rollback_of: Some(2),
        }];
        let v: serde_json::Value = serde_json::from_str(&render_json(&revs)).unwrap();
        assert_eq!(v[0]["rev_number"], 3);
        assert_eq!(v[0]["rollback_of"], 2);
        assert!(v[0]["content_hash"].is_null());
    }

    #[test]
    fn empty_history_is_empty_array() {
        assert_eq!(render_json(&[]), "[]");
    }
}
