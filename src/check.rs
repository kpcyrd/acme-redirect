use crate::args::CheckArgs;
use crate::chall::Challenge;
use crate::config::Config;
use crate::errors::*;
use std::collections::HashSet;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub fn check(name: &str, config: &Config) -> Result<()> {
    let mut chall = Challenge::new(config);
    let token = chall.random()?;
    let url = format!("http://{name}/.well-known/acme-challenge/{token}");
    let mut r = ureq::get(&url)
        .config()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .call()?;

    let status = r.status();
    if status != 200 {
        bail!(
            "response status code is wrong (expected 200, got {})",
            status
        );
    }

    let body = r.body_mut().read_to_string()?;
    if body != token {
        bail!("response body didn't match expected token");
    }

    chall.cleanup()?;

    Ok(())
}

pub fn run(config: Config, mut args: CheckArgs) -> Result<()> {
    let filter = args.certs.drain(..).collect::<HashSet<_>>();
    for cert in config.filter_certs(&filter) {
        for dns_name in &cert.dns_names {
            if let Err(err) = check(dns_name, &config) {
                error!(
                    "Check failed ({:?} -> {:?}): {:#}",
                    cert.name, dns_name, err
                );
            } else {
                info!("Verified {:?} -> {:?}: OK", cert.name, dns_name);
            }
        }
    }

    Ok(())
}
