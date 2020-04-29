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
use colored::Colorize;
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
                    let status = format!("{} days left", days_left);
                    let status = if days_left > config.renew_if_days_left {
                        status.green()
                    } else if days_left > 0 {
                        status.yellow()
                    } else {
                        status.red()
                    };
                    println!("{:50} {}", name.bold(), status);
                } else {
                    println!("{:50} -", name.bold());
                }
            }
        }
        SubCommand::Renew(args) => {
            let persist = FilePersist::new(&config);
            let mut challenge = Challenge::new(&config);

            // TODO: failing one cert shouldn't abort renew
            for cert in &config.certs {
                let request_cert = if args.force_renew {
                    info!("{:?}: force renewing", cert.name);
                    true
                } else if let Some(existing) = persist.load_cert_info(&cert.name)? {
                    let days_left = existing.days_left();
                    if days_left <= config.renew_if_days_left {
                        info!("{:?}: existing cert is below threshold", cert.name);
                        true
                    } else {
                        info!("{:?}: cert already satisfied", cert.name);
                        false
                    }
                } else {
                    info!("{:?}: creating new cert", cert.name);
                    true
                };

                if request_cert && args.dry_run {
                    info!("renewing {:?} (dry run)", cert.name);
                } else if request_cert {
                    info!("renewing {:?}", cert.name);
                    acme::request(
                        persist.clone(),
                        &mut challenge,
                        &acme::Request {
                            account_email: config.acme_email.as_deref(),
                            acme_url: &config.acme_url,
                            primary_name: &cert.name,
                            alt_names: &cert.dns_names,
                        },
                    )
                    .with_context(|| anyhow!("Fail to get certificate {:?}", cert.name))?;

                    challenge.cleanup()?;
                }
            }

            // TODO: cleanup unreferenced certs
            // TODO: pass dry-run flag
        }
    }

    Ok(())
}
