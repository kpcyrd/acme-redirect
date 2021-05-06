use crate::errors::*;
use std::io::stdout;
use std::path::PathBuf;
use structopt::clap::{AppSettings, Shell};
use structopt::StructOpt;

const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
// const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
pub struct Args {
    /// Verbose logging output (Can be set multiple times)
    #[structopt(short, long, global = true, parse(from_occurrences))]
    pub verbose: u8,
    /// Silent output (except errors)
    #[structopt(short, long, global = true)]
    pub quiet: bool,
    #[structopt(
        short,
        long,
        value_name = "path",
        default_value = "/etc/acme-redirect.conf",
        env = "ACME_CONFIG"
    )]
    pub config: String,
    #[structopt(
        long,
        value_name = "path",
        default_value = "/etc/acme-redirect.d",
        env = "ACME_CONFIG_DIR"
    )]
    pub config_dir: String,
    #[structopt(
        long,
        value_name = "path",
        default_value = "/run/acme-redirect",
        env = "ACME_CHALL_DIR"
    )]
    pub chall_dir: String,
    #[structopt(long, value_name = "path", env = "ACME_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    #[structopt(long, default_value=LETSENCRYPT, env="ACME_URL")]
    pub acme_url: String,
    #[structopt(long, env = "ACME_EMAIL")]
    pub acme_email: Option<String>,
    #[structopt(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Clone, StructOpt)]
pub enum SubCommand {
    #[structopt(flatten)]
    Cmds(Cmd),
    /// Generate shell completions
    Completions(Completions),
}

#[derive(Debug, Clone, StructOpt)]
pub enum Cmd {
    /// Run the redirect daemon
    Daemon(DaemonArgs),
    /// Show the status of our certificates
    Status,
    /// Request new certificates if needed
    Renew(RenewArgs),
    /// Check if the challenges could be completed
    Check(CheckArgs),
}

#[derive(Debug, Clone, StructOpt)]
pub struct DaemonArgs {
    /// The address to listen on
    #[structopt(short = "B", long, default_value = "[::]:80", env = "ACME_BIND_ADDR")]
    pub bind_addr: String,
    /// Drop from root to this user
    #[structopt(long)]
    pub user: Option<String>,
    /// Chroot into the challenge directory
    #[structopt(long)]
    pub chroot: bool,
}

#[derive(Debug, Clone, StructOpt)]
pub struct RenewArgs {
    /// Do not actually do anything, just show what would happen
    #[structopt(short = "n", long)]
    pub dry_run: bool,
    /// Renew certificates even if they are not about to expire
    #[structopt(long)]
    pub force_renew: bool,
    // TODO: add code to check if the cert actually fulfills the dns_names in the config
    /// Do not execute the configured exec commands
    #[structopt(long)]
    pub skip_restarts: bool,
    /// Don't clean up old certs that are not live anymore
    #[structopt(long)]
    pub skip_cleanup: bool,
    /// Only execute hooks without actually renewing certs
    #[structopt(long)]
    pub hooks_only: bool,
    /// Only renew specific certs
    pub certs: Vec<String>,
}

#[derive(Debug, Clone, StructOpt)]
pub struct CheckArgs {
    /// Only check specific certs
    pub certs: Vec<String>,
}

#[derive(Debug, Clone, StructOpt)]
pub struct Completions {
    #[structopt(possible_values=&Shell::variants())]
    pub shell: Shell,
}

pub fn gen_completions(args: &Completions) -> Result<()> {
    Args::clap().gen_completions_to("acme-redirect", args.shell, &mut stdout());
    Ok(())
}
