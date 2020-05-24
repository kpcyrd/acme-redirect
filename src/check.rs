use crate::args::CheckArgs;
use crate::chall::Challenge;
use crate::config::Config;
use crate::errors::*;
use std::collections::HashSet;

pub fn check(name: &str, token: &str) -> Result<()> {
    let url = format!("http://{}/.well-known/acme-challenge/{}", name, token);
    let r = ureq::get(&url)
        .timeout_connect(30_000)
        .timeout_read(30_000)
        .timeout_write(30_000)
        .call();

    let status = r.status();
    if status != 200 {
        bail!(
            "response status code is wrong (expected 200, got {})",
            status
        );
    }

    let body = r.into_string()?;
    if body != token {
        bail!("response body didn't match expected token");
    }

    Ok(())
}

pub fn run(config: Config, mut args: CheckArgs) -> Result<()> {
    let mut chall = Challenge::new(&config);
    let token = chall.random()?;

    let filter = args.certs.drain(..).collect::<HashSet<_>>();
    for cert in config.filter_certs(&filter) {
        for dns_name in &cert.dns_names {
            if let Err(err) = check(dns_name, &token) {
                error!(
                    "Check failed ({:?} -> {:?}): {:#}",
                    cert.name, dns_name, err
                );
            } else {
                info!("Verified {:?} -> {:?}: OK", cert.name, dns_name);
            }
        }
    }

    chall.cleanup()?;

    Ok(())
}
