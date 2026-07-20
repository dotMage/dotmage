//! `dmage sync [app]` — one verb for the 90% case.
//!
//! Decides by itself: remote ahead → pull; local changes → push; both moved →
//! show a key-level diff and stop (no auto-merge). Glue over push/pull/diff plus
//! a device-level base marker (see `dotmage_client::sync_state`).

use dotmage_client::types::RevSpec;

use super::{sha256_hex, CliError, Context};

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Push,
    Pull,
    Resolve,
}

/// Given whether the local file changed since the last sync and whether the
/// remote advanced past our base, pick the action. "Both" — and "unknown" (no
/// base marker, so both flags default true) — are never auto-resolved.
fn decide(local_changed: bool, remote_advanced: bool) -> Action {
    match (local_changed, remote_advanced) {
        (true, false) => Action::Push,
        (false, true) => Action::Pull,
        _ => Action::Resolve,
    }
}

pub fn run(ctx: &mut Context, app_arg: Option<&str>) -> Result<(), CliError> {
    let name = ctx.app_name(app_arg)?;
    let env_name = ctx.active_env.clone();

    // Remote latest also tells us the stored file name. If the app/env isn't on
    // the server yet, point at init rather than guessing.
    let (rev_number, remote) = ctx.pull_decoded(&name, &RevSpec::Latest).map_err(|_| {
        CliError::Other(format!("no remote revisions for '{name}' — run: dmage init {name}"))
    })?;

    let file = remote.meta.file_name.clone();
    let path = std::path::Path::new(&file);

    // No local copy here yet → just pull it down.
    if !path.exists() {
        ctx.print(&format!("no local {file} — pulling rev {rev_number}"));
        return super::pull::run(ctx, &name, None, None, false, true);
    }

    let local_data = std::fs::read(path)?;

    if local_data == remote.data {
        ctx.record_sync_state(&name, &env_name, rev_number, &file, &local_data);
        ctx.success(&format!("in sync (rev {rev_number}).{}", ctx.server_suffix()));
        return Ok(());
    }

    // Diverged — classify against the base marker.
    let entry = ctx.sync_state_entry(&name, &env_name);
    let local_changed = entry
        .as_ref()
        .map(|e| sha256_hex(&local_data) != e.hash)
        .unwrap_or(true);
    let remote_advanced = entry.as_ref().map(|e| rev_number > e.base_rev).unwrap_or(true);

    match decide(local_changed, remote_advanced) {
        Action::Push => {
            ctx.print("local changes → pushing");
            super::push::run(ctx, &name, None, false)
        }
        Action::Pull => {
            // Local is unmodified relative to base, so overwrite is safe (force
            // skips the redundant confirm prompt).
            ctx.print(&format!("remote ahead (rev {rev_number}) → pulling"));
            super::pull::run(ctx, &name, None, None, false, true)
        }
        Action::Resolve => {
            let why = if entry.is_none() {
                "no local sync record (first sync here, or the folder moved)"
            } else {
                "both local and remote changed"
            };
            ctx.print(&format!("{why} — no auto-merge, review and choose:"));
            super::diff::run(ctx, &name, false, None)?;
            ctx.print("resolve: `dmage pull` (overwrite local) or `dmage push` (upload local)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_only_pushes() {
        assert_eq!(decide(true, false), Action::Push);
    }
    #[test]
    fn remote_only_pulls() {
        assert_eq!(decide(false, true), Action::Pull);
    }
    #[test]
    fn both_changed_resolves() {
        assert_eq!(decide(true, true), Action::Resolve);
    }
    #[test]
    fn no_change_resolves() {
        // Reached only when local != remote yet neither flag tripped (stale
        // marker) — safest to ask rather than guess.
        assert_eq!(decide(false, false), Action::Resolve);
    }
}
