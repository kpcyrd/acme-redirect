use acme_redirect::args::{self, Args, Cmd, SubCommand};
use acme_redirect::check;
use acme_redirect::config;
use acme_redirect::daemon;
use acme_redirect::errors::*;
use acme_redirect::renew;
use acme_redirect::status;
use env_logger::Env;
use structopt::StructOpt;

fn main() -> Result<()> {
    let args = Args::from_args();

    let logging = match (args.quiet, args.verbose) {
        (true, _) => "warn",
        (false, 0) => "info",
        (false, 1) => "info,acme_redirect=debug",
        (false, 2) => "debug",
        (false, _) => "debug,acme_redirect=trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(logging));

    match args.subcommand.clone() {
        SubCommand::Cmds(subcommand) => {
            let config = config::load(&args)?;
            trace!("Loaded runtime config: {:?}", config);

            match subcommand {
                Cmd::Daemon(args) => daemon::run(config, args)?,
                Cmd::Status => status::run(config)?,
                Cmd::Renew(args) => renew::run(config, args)?,
                Cmd::Check(args) => check::run(config, args)?,
            }
        }
        SubCommand::Completions(completions) => args::gen_completions(&completions)?,
    }

    Ok(())
}
