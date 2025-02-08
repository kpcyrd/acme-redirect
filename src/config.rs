use crate::args::Args;
use crate::errors::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
// const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const DEFAULT_RENEW_IF_DAYS_LEFT: i64 = 30;
pub const BIND_ALL_PORT_80: &str = "[::]:80";

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub system: SystemConfig,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub acme_email: Option<String>,
    pub acme_url: String,
    pub renew_if_days_left: i64,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemConfig {
    pub addr: Option<String>,
    pub data_dir: PathBuf,
    pub chall_dir: PathBuf,
    #[serde(default)]
    pub exec: Vec<String>,
    #[serde(default)]
    pub exec_extra: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct CertConfigFile {
    cert: CertConfig,
}

fn load_str<T: DeserializeOwned>(s: &str) -> Result<T> {
    let conf = toml::from_str(s).context("Failed to load config")?;
    Ok(conf)
}

fn load_file<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T> {
    let buf = fs::read_to_string(path.as_ref()).context("Failed to read file")?;
    load_str(&buf)
}

fn load_from_folder<P: AsRef<Path>>(path: P) -> Result<Vec<CertConfigFile>> {
    let mut configs = Vec::new();
    let iter = fs::read_dir(path.as_ref())
        .with_context(|| anyhow!("Failed to list directory: {:?}", path.as_ref()))?;

    for file in iter {
        let file = file?;
        let path = file.path();

        if path.extension() == Some(OsStr::new("conf")) {
            let c = load_file(&path)
                .with_context(|| anyhow!("Failed to load config file {:?}", path))?;
            configs.push(c);
        } else {
            debug!("skipping non-config file {:?}", path);
        }
    }
    Ok(configs)
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    pub name: String,
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub must_staple: bool,
    #[serde(default)]
    pub exec: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub certs: Vec<CertConfig>,
    pub acme: AcmeConfig,
    pub system: SystemConfig,
}

impl Config {
    pub fn filter_certs<'a>(
        &'a self,
        filter: &'a HashSet<String>,
    ) -> impl Iterator<Item = &'a CertConfig> {
        self.certs
            .iter()
            .filter(move |cert| filter.is_empty() || filter.contains(&cert.name))
    }
}

pub fn load(args: Args) -> Result<Config> {
    let settings = config::Config::builder()
        .set_default("acme.acme_url", LETSENCRYPT)?
        .set_default("acme.renew_if_days_left", DEFAULT_RENEW_IF_DAYS_LEFT)?
        .set_default("system.data_dir", "/var/lib/acme-redirect")?
        .set_default("system.chall_dir", "/run/acme-redirect")?
        .add_source(config::File::new(&args.config, config::FileFormat::Toml))
        .set_override_option("acme.acme_email", args.acme_email)?
        .set_override_option("acme.acme_url", args.acme_url)?
        .set_override_option("system.data_dir", args.data_dir)?
        .set_override_option("system.chall_dir", args.chall_dir)?
        .build()
        .context("Failed to load config")?;

    let config = settings
        .try_deserialize::<ConfigFile>()
        .context("Failed to parse config")?;

    let certs = load_from_folder(&args.config_dir)?
        .into_iter()
        .map(|c| c.cert)
        .collect();

    Ok(Config {
        certs,
        acme: config.acme,
        system: config.system,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_cert_conf() {
        let conf = load_str::<CertConfigFile>(
            r#"
            [cert]
            name = "example.com"
            dns_names = ["example.com", "www.example.com"]
        "#,
        )
        .unwrap();

        assert_eq!(
            conf,
            CertConfigFile {
                cert: CertConfig {
                    name: "example.com".to_string(),
                    dns_names: vec!["example.com".to_string(), "www.example.com".to_string(),],
                    must_staple: false,
                    exec: vec![],
                },
            }
        );
    }
}
