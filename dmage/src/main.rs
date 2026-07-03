//! dmage — the dotMage CLI entry point.

use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod cmd;

#[derive(Parser)]
#[command(
    name = "dmage",
    version,
    about = "dotMage — E2E-encrypted .env secret manager",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Override the active environment.
    #[arg(long, global = true)]
    env: Option<String>,

    /// Server to use: a configured name, or a URL with `dmage auth`.
    #[arg(long, global = true)]
    server: Option<String>,

    /// Suppress non-error output.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// JSON output for scripting.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with the dotMage server.
    Auth {
        /// Name for the server added via --server <url> (default: its host).
        #[arg(long)]
        name: Option<String>,
        /// Enrollment token (for subsequent devices).
        #[arg(long)]
        enroll: Option<String>,
        /// Cache TTL (e.g., "7d", "30d").
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Initialize a new app from a local secrets file (.env, xml, json, ...).
    Init {
        /// Application name (default: current directory name).
        name: Option<String>,
        /// Path to the secrets file (default: ./.env).
        #[arg(long)]
        file: Option<String>,
        /// Content format: env | text | binary (default: detected from the file).
        #[arg(long)]
        format: Option<String>,
        /// Allow an empty file.
        #[arg(long)]
        allow_empty: bool,
    },
    /// Push the local secrets file as a new revision.
    Push {
        /// Application name (default: current directory name).
        name: Option<String>,
        /// Path to the secrets file (default: the name stored in the app).
        #[arg(long)]
        file: Option<String>,
        /// Allow pushing an empty file.
        #[arg(long)]
        allow_empty: bool,
    },
    /// Pull secrets and write to .env file.
    Pull {
        /// Application name (default: current directory name).
        name: Option<String>,
        /// Specific revision (default: latest).
        #[arg(long)]
        rev: Option<String>,
        /// Output file path.
        #[arg(long)]
        output: Option<String>,
        /// Write to stdout instead of file.
        #[arg(long)]
        stdout: bool,
        /// Overwrite without confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Run a command with secrets injected (e.g., dmage exec myapp npm dev).
    Exec {
        /// Application name.
        name: String,
        /// Command and arguments (no -- needed).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show diff between local and remote.
    Diff {
        /// Application name (default: current directory name).
        name: Option<String>,
        /// Local file to compare (default: the name stored in the app).
        #[arg(long)]
        file: Option<String>,
        /// Show actual values (locally only).
        #[arg(long)]
        show_values: bool,
    },
    /// Show revision history.
    History {
        /// Application name (default: current directory name).
        name: Option<String>,
    },
    /// Rollback to a previous revision.
    Rollback {
        /// Application name (default: current directory name).
        name: Option<String>,
        /// Target revision number.
        #[arg(long)]
        rev: u64,
    },
    /// List all applications.
    Apps,
    /// Manage applications.
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// Generate a one-time login token for the web admin.
    Token,
    /// Generate a scoped CI token for a specific app+env.
    GenCiToken {
        /// Application name.
        #[arg(long)]
        app: String,
        /// Environment name.
        #[arg(long)]
        env: String,
        /// TTL (e.g., "30d").
        #[arg(long, default_value = "30d")]
        ttl: String,
    },
    /// Manage servers (work/personal, directory mappings).
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Show sync status.
    Status,
    /// Remove cached key (keep device token).
    Lock {
        /// Lock all configured servers.
        #[arg(long)]
        all: bool,
    },
    /// Full logout (key + tokens + local data).
    Logout {
        /// Log out of all configured servers.
        #[arg(long)]
        all: bool,
    },
    /// Wipe all local dotMage data from this device.
    Clean,
    /// Generate enrollment/CI token.
    GenToken {
        /// Token name.
        #[arg(long)]
        name: Option<String>,
        /// TTL (e.g., "24h").
        #[arg(long, default_value = "24h")]
        ttl: String,
    },
    /// Upgrade dmage to the latest release.
    Upgrade {
        /// Only check for a new version, don't install.
        #[arg(long)]
        check: bool,
        /// Install a specific version (default: latest).
        #[arg(long)]
        version: Option<String>,
        /// Reinstall/downgrade even if not newer.
        #[arg(long)]
        force: bool,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Manage environments.
    Env {
        #[command(subcommand)]
        action: Option<EnvAction>,
    },
    /// Show help.
    Help,
}

#[derive(Subcommand)]
enum ServerAction {
    /// List configured servers.
    List,
    /// Add or update a server.
    Add {
        /// Server name (e.g., work).
        name: String,
        /// Server URL.
        url: String,
        /// Directory to map to this server (repeatable).
        #[arg(long)]
        path: Vec<String>,
    },
    /// Map a directory to a server.
    Map {
        /// Server name.
        name: String,
        /// Directory path.
        path: String,
    },
    /// Remove a directory mapping.
    Unmap {
        /// Server name.
        name: String,
        /// Directory path.
        path: String,
    },
    /// Remove a server (wipes its local tokens + cached key).
    Rm {
        /// Server name.
        name: String,
        /// Skip confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Set the fallback server for unmapped directories.
    Use {
        /// Server name.
        name: String,
    },
    /// Rename a server.
    Rename {
        /// Current name.
        old: String,
        /// New name.
        new: String,
    },
}

#[derive(Subcommand)]
enum AppAction {
    /// Delete an application and all its environments.
    Rm {
        /// Application name.
        name: String,
        /// Skip confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum EnvAction {
    /// List all environments for the active app.
    List {
        /// Application name.
        name: String,
    },
    /// Create a new environment.
    New {
        /// Application name.
        app: String,
        /// Environment name.
        name: String,
        /// Copy from existing environment.
        #[arg(long)]
        copy_from: Option<String>,
    },
    /// Delete an environment.
    Rm {
        /// Application name.
        app: String,
        /// Environment name.
        name: String,
        /// Skip confirmation.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.command.is_none() {
        print_banner();
        return ExitCode::SUCCESS;
    }

    let result = run(cli);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\x1b[31m  error:\x1b[0m {e}");
            e.exit_code()
        }
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Derive a server name from its URL host (`https://secrets.corp.com` → `secrets.corp.com`).
fn name_from_url(url: &str) -> String {
    cmd::host_of(url)
        .split(['/', ':'])
        .next()
        .unwrap_or("server")
        .to_string()
}

fn run(cli: Cli) -> Result<(), cmd::CliError> {
    let command = cli.command.unwrap();

    if matches!(command, Commands::Help) {
        use clap::CommandFactory;
        Cli::command().print_help().ok();
        println!();
        return Ok(());
    }

    // --server takes a configured name; a URL is accepted only with `dmage auth`,
    // where it registers the server first.
    let mut server_override = cli.server.clone();
    let mut auth_url: Option<String> = None;
    if let Some(ref s) = cli.server {
        if is_url(s) {
            if let Commands::Auth { ref name, .. } = command {
                let url = s.trim_end_matches('/').to_string();
                let name = name.clone().unwrap_or_else(|| name_from_url(&url));
                register_server(&url, &name)?;
                server_override = Some(name);
                auth_url = Some(url);
            } else {
                return Err(cmd::CliError::Config(format!(
                    "--server expects a configured name here; to add '{s}' run: dmage auth --server {s} --name <name>"
                )));
            }
        }
    }

    let mut ctx = cmd::Context::load(cli.env, server_override, cli.quiet, cli.json)?;

    match command {
        Commands::Auth { ttl, enroll, .. } => {
            if auth_url.is_some() && ctx.config.servers.len() > 1 && !cli.quiet {
                println!(
                    "  \x1b[90mhint: map a projects dir to this server: dmage server map {} ~/code/...\x1b[0m",
                    ctx.server.as_ref().map(|(n, _)| n.as_str()).unwrap_or("<name>")
                );
            }
            cmd::auth::run(&mut ctx, ttl, enroll)
        }
        Commands::Init {
            name,
            file,
            format,
            allow_empty,
        } => {
            let app = ctx.app_name(name.as_deref())?;
            cmd::init::run(
                &mut ctx,
                &app,
                file.as_deref(),
                format.as_deref(),
                allow_empty,
            )
        }
        Commands::Push {
            name,
            file,
            allow_empty,
        } => {
            let app = ctx.app_name(name.as_deref())?;
            cmd::push::run(&mut ctx, &app, file.as_deref(), allow_empty)
        }
        Commands::Pull {
            name,
            rev,
            output,
            stdout,
            force,
        } => {
            let app = ctx.app_name(name.as_deref())?;
            cmd::pull::run(
                &mut ctx,
                &app,
                rev.as_deref(),
                output.as_deref(),
                stdout,
                force,
            )
        }
        Commands::Exec { name, command } => cmd::exec::run(&mut ctx, &name, &command),
        Commands::Diff {
            name,
            file,
            show_values,
        } => {
            let app = ctx.app_name(name.as_deref())?;
            cmd::diff::run(&mut ctx, &app, show_values, file.as_deref())
        }
        Commands::History { name } => {
            let app = ctx.app_name(name.as_deref())?;
            cmd::history::run(&ctx, &app)
        }
        Commands::Rollback { name, rev } => {
            let app = ctx.app_name(name.as_deref())?;
            cmd::rollback::run(&mut ctx, &app, rev)
        }
        Commands::Apps => cmd::apps::run(&ctx),
        Commands::App { action } => match action {
            AppAction::Rm { name, yes } => cmd::app_rm::run(&ctx, &name, yes),
        },
        Commands::Token => cmd::token_cmd::run(&ctx),
        Commands::GenCiToken { app, env, ttl } => cmd::gen_ci_token::run(&ctx, &app, &env, &ttl),
        Commands::Server { action } => {
            let server_cmd = match action {
                ServerAction::List => cmd::server::ServerCmd::List,
                ServerAction::Add { name, url, path } => cmd::server::ServerCmd::Add {
                    name,
                    url,
                    paths: path,
                },
                ServerAction::Map { name, path } => cmd::server::ServerCmd::Map { name, path },
                ServerAction::Unmap { name, path } => cmd::server::ServerCmd::Unmap { name, path },
                ServerAction::Rm { name, yes } => cmd::server::ServerCmd::Rm { name, yes },
                ServerAction::Use { name } => cmd::server::ServerCmd::Use { name },
                ServerAction::Rename { old, new } => cmd::server::ServerCmd::Rename { old, new },
            };
            cmd::server::run(&mut ctx, server_cmd)
        }
        Commands::Status => cmd::status::run(&ctx),
        Commands::Lock { all } => cmd::lock::run(&ctx, all),
        Commands::Logout { all } => cmd::lock::run_logout(&ctx, all),
        Commands::Clean => cmd::clean::run(&ctx),
        Commands::GenToken { name, ttl } => cmd::gen_token::run(&ctx, name.as_deref(), &ttl),
        Commands::Upgrade {
            check,
            version,
            force,
            yes,
        } => cmd::upgrade::run(&ctx, check, version.as_deref(), force, yes),
        Commands::Env { action } => cmd::env::run(
            &ctx,
            action.map(|a| match a {
                EnvAction::List { name } => cmd::env::EnvCmd::List(name),
                EnvAction::New {
                    app,
                    name,
                    copy_from,
                } => cmd::env::EnvCmd::New(app, name, copy_from),
                EnvAction::Rm { app, name, yes } => cmd::env::EnvCmd::Rm(app, name, yes),
            }),
        ),
        Commands::Help => unreachable!(),
    }
}

/// Register/update a named server in the config BEFORE Context resolution,
/// so `dmage auth --server <url>` works even from an ambiguous state.
fn register_server(url: &str, name: &str) -> Result<(), cmd::CliError> {
    let mut config =
        dotmage_client::config::Config::load().map_err(|e| cmd::CliError::Config(e.to_string()))?;
    config.migrate_legacy();
    let entry = config.servers.entry(name.to_string()).or_default();
    entry.url = url.to_string();
    if config.active_server.is_none() {
        config.active_server = Some(name.to_string());
    }
    config
        .save()
        .map_err(|e| cmd::CliError::Config(e.to_string()))
}

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("\x1b[36m");
    println!("      ·  dotMage  ·");
    println!("\x1b[0m");
    println!("  E2E-encrypted .env manager  v{version}");
    println!();

    // Show connection status. Solo invariant: with 0–1 servers this looks
    // exactly like the pre-multi-server banner.
    let mut config = dotmage_client::config::Config::load().unwrap_or_default();
    config.migrate_legacy(); // display only; persisted on first real command
    match config.servers.len() {
        0 => println!("  server   \x1b[90m(local mode)\x1b[0m"),
        1 => {
            let entry = config.servers.values().next().unwrap();
            println!("  server   \x1b[90m{}\x1b[0m", entry.url);
            println!("  auth     {}", cmd::server::auth_state(&entry.url));
        }
        _ => {
            println!("  servers");
            for (name, entry) in &config.servers {
                let marker = if config.active_server.as_deref() == Some(name) {
                    "*"
                } else {
                    " "
                };
                let paths = if entry.paths.is_empty() {
                    String::new()
                } else {
                    format!("   \x1b[90m{}\x1b[0m", entry.paths.join(", "))
                };
                println!(
                    "   {marker} {name:<12} \x1b[90m{:<26}\x1b[0m {}{paths}",
                    cmd::host_of(&entry.url),
                    cmd::server::auth_state(&entry.url)
                );
            }
        }
    }

    // Update check
    if let Some(latest) = cmd::upgrade::check_for_update() {
        println!();
        println!("  \x1b[33mupdate available: v{latest}  (current: v{version})\x1b[0m");
        println!("  \x1b[90mrun: \x1b[0mdmage upgrade");
    }

    println!();
    println!("  \x1b[90mRun \x1b[0mdmage help\x1b[90m for commands\x1b[0m");
    println!();
}
