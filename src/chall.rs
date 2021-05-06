use crate::config::Config;
use crate::errors::*;
use rand::seq::SliceRandom;
use std::fs;
use std::path::{Path, PathBuf};

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
        let chall_dir = Path::new(&config.system.chall_dir);
        // TODO: consider creating the directory
        Challenge {
            path: chall_dir.join("challs"),
            written: Vec::new(),
        }
    }

    pub fn write(&mut self, token: &str, proof: &str) -> Result<()> {
        if !valid_token(token) {
            bail!("ACME server sent us malicious token")
        }

        let path = self.path.join(token);
        debug!("Writing challenge proof to {:?}", path);
        fs::write(&path, proof).context("Failed to write challenge proof")?;

        self.written.push(path);

        Ok(())
    }

    pub fn random(&mut self) -> Result<String> {
        const TOKEN_LEN: usize = 16;
        let mut rng = rand::thread_rng();

        let random = VALID_CHARS
            .as_bytes()
            .choose_multiple(&mut rng, TOKEN_LEN)
            .map(|b| *b as char)
            .collect::<String>();

        self.write(&random, &random)?;
        Ok(random)
    }

    pub fn cleanup(&mut self) -> Result<()> {
        for path in self.written.drain(..) {
            debug!("Deleting old challenge proof: {:?}", path);
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
