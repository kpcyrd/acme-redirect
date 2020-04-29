mod acme;
mod args;
mod cert;
mod chall;
mod renew;
mod config;
mod daemon;
mod errors;
mod status;
mod http_responses;
mod persist;

use crate::args::{Args, SubCommand};
use crate::errors::*;
use env_logger::Env;
use structopt::StructOpt;

fn main() -> Result<()> {
    let args = Args::from_args();

    let logging = match args.verbose {
        0 => "info",
        1 => "acme-redirect=debug",
        _ => "debug",
    };
    env_logger::init_from_env(Env::default().default_filter_or(logging));

    let config = config::load(&args)?;
    debug!("Loaded runtime config: {:?}", config);

    match args.subcommand {
        SubCommand::Setup(_args) => (),
        SubCommand::Daemon(args) => daemon::run(config, args)?,
        SubCommand::Status => status::run(config)?,
        SubCommand::Renew(args) => renew::run(config, args)?,
        SubCommand::Completions(completions) => args::gen_completions(&completions)?,
    }

    Ok(())
}
