use std::process::Command;
use crate::args::RenewArgs;
use crate::config::CertConfig;
use crate::config::Config;
use crate::acme;
use crate::chall::Challenge;
use crate::errors::*;
use crate::persist::FilePersist;

fn should_request_cert(args: &RenewArgs, config: &Config, persist: &FilePersist, cert: &CertConfig) -> Result<bool> {
    if args.force_renew {
        info!("{:?}: force renewing", cert.name);
        Ok(true)
    } else if let Some(existing) = persist.load_cert_info(&cert.name)? {
        let days_left = existing.days_left();
        if days_left <= config.renew_if_days_left {
            info!("{:?}: existing cert is below threshold", cert.name);
            Ok(true)
        } else {
            info!("{:?}: cert already satisfied", cert.name);
            Ok(false)
        }
    } else {
        info!("{:?}: creating new cert", cert.name);
        Ok(true)
    }
}

fn execute_hooks(hooks: &[String], dry_run: bool) -> Result<()> {
    for exec in hooks {
        if dry_run {
            info!("executing hook: {:?} (dry run)", exec);
        } else {
            info!("executing hook: {:?}", exec);

            let status = Command::new("sh")
                .arg("-c")
                .arg(exec)
                .status()
                .context("Failed to spawn shell for hook")?;

            if !status.success() {
                error!("Failed to execute hook: {:?}", exec);
            }
        }
    }
    Ok(())
}

fn renew_cert(args: &RenewArgs, config: &Config, persist: &FilePersist, cert: &CertConfig) -> Result<()> {
    let mut challenge = Challenge::new(&config);
    let request_cert = should_request_cert(&args, &config, &persist, &cert)?;

    if request_cert && args.dry_run {
        info!("renewing {:?} (dry run)", cert.name);
        execute_hooks(&cert.exec, args.skip_restarts)?;
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

        execute_hooks(&cert.exec, args.skip_restarts)?;
    }

    Ok(())
}

fn cleanup_certs(_dry_run: bool) -> Result<()> {
    // debug!("TODO: cleanup old certs");
    Ok(())
}

pub fn run(config: Config, args: RenewArgs) -> Result<()> {
    let persist = FilePersist::new(&config);

    for cert in &config.certs {
        if let Err(err) = renew_cert(&args, &config, &persist, &cert) {
            error!("Failed to renew: {:#}", err);
        }
    }

    cleanup_certs(args.dry_run)?;

    Ok(())
}
