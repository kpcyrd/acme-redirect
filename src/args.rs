use crate::errors::*;
use clap::{ArgAction, CommandFactory, Parser};
use clap_complete::Shell;
use std::io::stdout;

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Verbose logging output (Can be set multiple times)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,
    /// Silent output (except errors)
    #[arg(short, long, global = true)]
    pub quiet: bool,
    #[arg(
        short,
        long,
        value_name = "path",
        default_value = "/etc/acme-redirect.conf",
        env = "ACME_CONFIG"
    )]
    pub config: String,
    #[arg(
        long,
        value_name = "path",
        default_value = "/etc/acme-redirect.d",
        env = "ACME_CONFIG_DIR"
    )]
    pub config_dir: String,
    #[arg(long, value_name = "path", env = "ACME_CHALL_DIR")]
    pub chall_dir: Option<String>,
    #[arg(long, value_name = "path", env = "ACME_DATA_DIR")]
    pub data_dir: Option<String>,
    #[arg(long, env = "ACME_URL")]
    pub acme_url: Option<String>,
    #[arg(long, env = "ACME_EMAIL")]
    pub acme_email: Option<String>,
    #[clap(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Clone, Parser)]
pub enum SubCommand {
    #[clap(flatten)]
    Cmds(Cmd),
    /// Generate shell completions
    Completions(Completions),
}

#[derive(Debug, Clone, Parser)]
pub enum Cmd {
    /// Run the redirect daemon
    Daemon(DaemonArgs),
    /// Show the status of our certificates
    Status,
    /// Request new certificates if needed
    Renew(RenewArgs),
    /// Check if the challenges could be completed
    Check(CheckArgs),
    /// Load the configuration and dump it to stdout as json
    DumpConfig,
}

#[derive(Debug, Clone, Parser)]
pub struct DaemonArgs {
    /// The address to listen on
    #[arg(short = 'B', long, default_value = "[::]:80", env = "ACME_BIND_ADDR")]
    pub bind_addr: String,
    /// Drop from root to this user
    #[arg(long)]
    pub user: Option<String>,
    /// Chroot into the challenge directory
    #[arg(long)]
    pub chroot: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct RenewArgs {
    /// Do not actually do anything, just show what would happen
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// Renew certificates even if they are not about to expire
    #[arg(long)]
    pub force_renew: bool,
    // TODO: add code to check if the cert actually fulfills the dns_names in the config
    /// Do not execute the configured exec commands
    #[arg(long)]
    pub skip_restarts: bool,
    /// Don't clean up old certs that are not live anymore
    #[arg(long)]
    pub skip_cleanup: bool,
    /// Only execute hooks without actually renewing certs
    #[arg(long)]
    pub hooks_only: bool,
    /// Only renew specific certs
    pub certs: Vec<String>,
}

#[derive(Debug, Clone, Parser)]
pub struct CheckArgs {
    /// Only check specific certs
    pub certs: Vec<String>,
}

#[derive(Debug, Clone, Parser)]
pub struct Completions {
    pub shell: Shell,
}

pub fn gen_completions(args: &Completions) -> Result<()> {
    clap_complete::generate(
        args.shell,
        &mut Args::command(),
        "acme-redirect",
        &mut stdout(),
    );
    Ok(())
}
