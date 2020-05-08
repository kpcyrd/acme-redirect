use crate::cert::CertInfo;
use crate::config::Config;
use crate::errors::*;
use acme_micro::Certificate;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::fs::{DirEntry, File, OpenOptions};
use std::io::prelude::*;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone)]
pub struct FilePersist {
    path: PathBuf,
}

fn create(path: &Path, mode: u32) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(Error::from)
}

impl FilePersist {
    pub fn new(config: &Config) -> FilePersist {
        FilePersist {
            path: config.data_dir.to_owned(),
        }
    }

    fn acc_privkey_path(&self) -> PathBuf {
        self.path.join("acc.key")
    }

    pub fn load_acc_privkey(&self) -> Result<Option<String>> {
        let path = self.acc_privkey_path();
        if path.exists() {
            let buf = fs::read_to_string(&path)?;
            Ok(Some(buf))
        } else {
            Ok(None)
        }
    }

    fn certstore_entry(entry: &DirEntry) -> Result<(PathBuf, String, CertInfo)> {
        let cert_path = entry.path().join("fullchain");

        let name = entry.file_name().into_string()
            .map_err(|_| anyhow!("Filename contains invalid utf8"))?;

        let buf = fs::read(cert_path)?;
        let cert = CertInfo::from_pem(&buf)?;

        Ok((
            entry.path(),
            name,
            cert,
        ))
    }

    pub fn list_certs(&self) -> Result<Vec<(PathBuf, String, CertInfo)>> {
        let path = self.path.join("certs");

        let mut certs = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            match Self::certstore_entry(&entry) {
                Ok(entry) => certs.push(entry),
                Err(err) => error!("Failed to read {:?}: {:#}", entry.path(), err),
            }
        }

        Ok(certs)
    }

    pub fn list_live_certs(&self) -> Result<HashMap<String, String>> {
        let path = self.path.join("live");

        let mut live = HashMap::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(Some(name)) = path.file_name().map(OsStr::to_str) {
                if let Ok(link) = fs::read_link(entry.path()) {
                    if let Some(Some(version)) = link.file_name().map(OsStr::to_str) {
                        live.insert(version.to_string(), name.to_string());
                    }
                }
            }
        }

        Ok(live)
    }

    pub fn load_cert_info(&self, name: &str) -> Result<Option<CertInfo>> {
        let mut path = self.path.join("live");
        path.push(name);
        path.push("fullchain");

        if path.exists() {
            let buf = fs::read(&path)?;
            let cert = CertInfo::from_pem(&buf)?;
            Ok(Some(cert))
        } else {
            Ok(None)
        }
    }

    pub fn store_acc_privkey(&self, key: &str) -> Result<()> {
        let path = self.acc_privkey_path();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;

        file.write_all(key.as_bytes())?;
        Ok(())
    }

    pub fn store_cert(&self, name: &str, cert: &Certificate) -> Result<()> {
        let now = time::now_utc();
        let now = time::strftime("%Y%m%d", &now)?;

        let path = self.path.join("certs");
        debug!("creating folder: {:?}", path);
        fs::create_dir_all(&path).with_context(|| anyhow!("Failed to create folder: {:?}", &path))?;

        let mut i = 0;
        let path = loop {
            let mut folder = now.clone() + "-" + name;
            if i > 0 {
                folder.push_str(&format!("-{}", i));
            }

            let path = path.join(folder);
            debug!("try atomically claiming folder: {:?}", path);

            let err = fs::create_dir(&path);
            match err {
                Err(e) if e.kind() == ErrorKind::AlreadyExists => (),
                Err(_) => {
                    err.with_context(|| anyhow!("Failed to create folder: {:?}", &path))?;
                }
                Ok(_) => break path,
            }

            i += 1;
        };

        debug!("writing privkey");
        let privkey = path.join("privkey");
        {
            let mut f = create(&privkey, 0o640)?;
            f.write_all(cert.private_key().as_bytes())?;
        }

        debug!("writing cert");
        let fullkey = path.join("fullchain");
        {
            let mut f = create(&fullkey, 0o644)?;
            f.write_all(cert.certificate().as_bytes())?;
        }

        info!("marking cert live");
        let live = self.path.join("live");
        fs::create_dir_all(&live)
            .with_context(|| anyhow!("Failed to create folder: {:?}", &live))?;
        let live = live.join(name);

        // TODO: this should be atomic (ln -sf)
        // https://github.com/coreutils/coreutils/blob/2ed7c2867974ccf7abc61c34ad7bf9565489c18e/src/force-link.c#L142-L182
        if live.exists() {
            fs::remove_file(&live).context("Failed to delete old symlink")?;
        }
        symlink(&path, &live)
            .with_context(|| anyhow!("Failed to create symlink: {:?} -> {:?}", path, live))?;

        Ok(())
    }
}
