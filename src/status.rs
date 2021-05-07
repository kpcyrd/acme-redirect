use crate::config::Config;
use crate::errors::*;
use crate::persist::FilePersist;
use colored::Colorize;
use nix::unistd::AccessFlags;
use std::path::Path;

pub fn run(config: Config) -> Result<()> {
    let persist = FilePersist::new(&config);

    let data_dir = Path::new(&config.system.data_dir);
    nix::unistd::access(data_dir, AccessFlags::X_OK)
        .with_context(|| anyhow!("Detected insufficient permissions to access {:?}", data_dir))?;

    for cert in config.certs {
        let name = cert.name;
        // TODO: also show alt names?
        if let Some(cert) = persist.load_cert_info(&name)? {
            let days_left = cert.days_left();
            let status = format!("{} days left", days_left);
            let status = if days_left > config.acme.renew_if_days_left {
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

    Ok(())
}
