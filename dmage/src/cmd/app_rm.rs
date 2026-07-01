//! `dmage app rm <name>` — delete an application and all its environments.

use super::{CliError, Context};

pub fn run(ctx: &Context, name: &str, yes: bool) -> Result<(), CliError> {
    if !yes {
        eprint!("Delete app '{name}' and ALL its environments? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            return Err(CliError::Other("aborted".into()));
        }
    }

    ctx.backend.delete_app(name)?;
    ctx.success(&format!("Deleted app '{name}'."));
    Ok(())
}
