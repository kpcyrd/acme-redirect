use crate::cert::CertInfo;
use crate::config::Config;
use crate::errors::*;
use acme_lib::persist::Persist;
use acme_lib::persist::PersistKey;
use acme_lib::persist::PersistKind;
use std::fs;
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

    fn path_and_perms(&self, key: &PersistKey) -> (PathBuf, u32) {
        let (folder, ext, mode) = match key.kind {
            PersistKind::Certificate => (self.path.join("certs"), "crt", 0o644),
            PersistKind::PrivateKey => (self.path.join("privs"), "key", 0o640),
            PersistKind::AccountPrivateKey => (self.path.join("accs"), "key", 0o600),
        };

        let mut f_name = folder;
        f_name.push(key.to_string());
        f_name.set_extension(ext);
        (f_name, mode)
    }
}

impl Persist for FilePersist {
    fn put(&self, key: &PersistKey, value: &[u8]) -> acme_lib::Result<()> {
        let (f_name, mode) = self.path_and_perms(&key);

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
        let (f_name, _) = self.path_and_perms(&key);
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
