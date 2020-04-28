mod acme;
mod args;
mod cert;
mod chall;
mod config;
mod daemon;
mod errors;
mod http_responses;
mod persist;

use crate::args::{Args, SubCommand};
use crate::chall::Challenge;
use crate::errors::*;
use crate::persist::FilePersist;
use env_logger::Env;
use structopt::StructOpt;

fn main() -> Result<()> {
    let args = Args::from_args();

    let logging = if args.verbose { "debug" } else { "info" };
    env_logger::init_from_env(Env::default().default_filter_or(logging));

    let config = config::load(&args)?;
    debug!("Loaded runtime config: {:?}", config);

    match args.subcommand {
        SubCommand::Setup(_args) => (),
        SubCommand::Daemon(args) => daemon::run(config, args)?,
        SubCommand::Status => {
            let persist = FilePersist::new(&config);

            for cert in config.certs {
                let name = cert.name;
                // TODO: also show alt names?
                if let Some(cert) = persist.load_cert_info(&name)? {
                    let days_left = cert.days_left();
                    println!("{:50} {:?}", name, days_left);
                } else {
                    println!("{:50} -", name);
                }
            }
        }
        SubCommand::Renew(_args) => {
            let persist = FilePersist::new(&config);
            let mut challenge = Challenge::new(&config);

            for cert in &config.certs {
                // if needs renew
                acme::request(
                    persist.clone(),
                    &mut challenge,
                    &acme::Request {
                        account_email: &config.acme_email,
                        acme_url: &config.acme_url,
                        primary_name: &cert.name,
                        alt_names: &cert.dns_names,
                    },
                )
                .with_context(|| anyhow!("Fail to get certificate {:?}", cert.name))?;

                challenge.cleanup()?;
            }
        }
    }

    Ok(())
}
