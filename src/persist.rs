use acme_lib::Certificate;
use std::os::unix::fs::symlink;
use acme_lib::persist::{Persist, PersistKey, PersistKind};
use crate::cert::CertInfo;
use crate::config::Config;
use crate::errors::*;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Clone)]
pub struct FilePersist {
    path: PathBuf,
}

// TODO: there should be a folder with all the certs
// TODO: there should be a symlink to the current cert
// TODO: there should be a way to get the current cert for a given name
// TODO: there should be a way to get the expire date of that cert

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

    pub fn load_cert_info(&self, name: &str) -> Result<Option<CertInfo>> {
        let key = PersistKey::new("", PersistKind::Certificate, name);
        if let Some(cert) = self.get(&key)? {
            // TODO: should an invalid cert prevent us from renewing it?
            let cert = CertInfo::from_pem(&cert)?;
            Ok(Some(cert))
        } else {
            Ok(None)
        }
    }

    pub fn store_cert(&self, name: &str, cert: &Certificate) -> Result<()> {
        let now = time::now_utc();
        let now = time::strftime("%Y%m%d", &now)?;

        let folder = now + "-" + name;
        let path = self.path.join("certs").join(&folder);
        debug!("creating folder: {:?}", path);
        fs::create_dir_all(&path)
            .with_context(|| anyhow!("Failed to create folder: {:?}", &path))?;

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
            fs::remove_file(&live)
                .context("Failed to delete old symlink")?;
        }
        symlink(&path, &live)
            .with_context(|| anyhow!("Failed to create symlink: {:?} -> {:?}", path, live))?;

        Ok(())
    }

    fn path_and_perms(&self, key: &PersistKey) -> Result<(PathBuf, u32)> {
        let (folder, ext, mode) = match key.kind {
            PersistKind::Certificate => (self.path.join("certs"), "crt", 0o644),
            PersistKind::PrivateKey => (self.path.join("privs"), "key", 0o640),
            PersistKind::AccountPrivateKey => (self.path.join("accs"), "key", 0o600),
        };

        if !folder.exists() {
            fs::create_dir(&folder)
                .with_context(|| anyhow!("Failed to create folder: {:?}", folder))?;
        }

        let mut f_name = folder;
        f_name.push(key.to_string());
        f_name.set_extension(ext);
        Ok((f_name, mode))
    }
}

impl Persist for FilePersist {
    fn put(&self, key: &PersistKey, value: &[u8]) -> acme_lib::Result<()> {
        let (f_name, mode) = self.path_and_perms(&key)
            .map_err(|e| e.to_string())?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(f_name)?;

        file.write_all(value)?;
        Ok(())
    }

    fn get(&self, key: &PersistKey) -> acme_lib::Result<Option<Vec<u8>>> {
        let (f_name, _) = self.path_and_perms(&key)
            .map_err(|e| e.to_string())?;
        let ret = if let Ok(mut file) = fs::File::open(f_name) {
            let mut v = vec![];
            file.read_to_end(&mut v)?;
            Some(v)
        } else {
            None
        };
        Ok(ret)
    }
}
