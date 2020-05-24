use crate::config::Config;
use crate::errors::*;
use std::fs;
use std::path::PathBuf;

const VALID_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[inline]
pub fn valid_token(t: &str) -> bool {
    t.chars().all(|c| VALID_CHARS.contains(c))
}

pub struct Challenge {
    path: PathBuf,
    written: Vec<PathBuf>,
}

impl Challenge {
    pub fn new(config: &Config) -> Challenge {
        // TODO: consider creating the directory
        Challenge {
            path: config.chall_dir.join("challs"),
            written: Vec::new(),
        }
    }

    pub fn write(&mut self, token: &str, proof: &str) -> Result<()> {
        if !valid_token(token) {
            bail!("ACME server sent us malicious token")
        }

        let path = self.path.join(token);
        fs::write(&path, proof)?;

        self.written.push(path);

        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<()> {
        for path in self.written.drain(..) {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
