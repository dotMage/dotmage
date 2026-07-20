//! `dmage completions <shell>` — print a shell completion script to stdout.
//!
//! Pure output from the clap command tree; needs no server, config or keys.
//! Redirect it where your shell looks, e.g. `dmage completions zsh > ~/.zfunc/_dmage`.
//! Homebrew installs these automatically via `generate_completions_from_executable`.

use std::io;

use clap::CommandFactory;
use clap_complete::{generate, Shell};

use crate::Cli;

pub fn run(shell: Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut io::stdout());
}
