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

impl FilePersist {
    pub fn new(config: &Config) -> FilePersist {
        FilePersist {
            path: PathBuf::from(&config.system.data_dir),
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

        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("Filename contains invalid utf8"))?;

        let buf = fs::read(cert_path)?;
        let cert = CertInfo::from_pem(&buf)?;

        Ok((entry.path(), name, cert))
    }

    pub fn list_certs(&self) -> Result<Vec<(PathBuf, String, CertInfo)>> {
        let path = self.path.join("certs");

        let mut certs = Vec::new();
        if path.exists() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                match Self::certstore_entry(&entry) {
                    Ok(entry) => certs.push(entry),
                    Err(err) => error!("Failed to read {:?}: {:#}", entry.path(), err),
                }
            }
        }

        Ok(certs)
    }

    pub fn list_live_certs(&self) -> Result<HashMap<String, String>> {
        let path = self.path.join("live");

        let mut live = HashMap::new();
        if path.exists() {
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

    pub fn store_cert(&self, name: &str, fullcert: &Certificate) -> Result<()> {
        let now = time::now_utc();
        let now = time::strftime("%Y%m%d", &now)?;

        let path = self.path.join("certs");
        debug!("creating folder: {:?}", path);
        fs::create_dir_all(&path)
            .with_context(|| anyhow!("Failed to create folder: {:?}", &path))?;

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

        debug!("splitting chain from cert");
        let (chain, cert) = split_chain(fullcert.certificate())?;

        let bundle = format!("{}{}", fullcert.private_key(), cert);

        debug!("writing privkey");
        let privkey_path = path.join("privkey");
        write(&privkey_path, 0o440, fullcert.private_key().as_bytes())?;

        debug!("writing full cert with intermediates");
        let fullkey_path = path.join("fullchain");
        write(&fullkey_path, 0o444, fullcert.certificate().as_bytes())?;

        debug!("writing chain");
        let chain_path = path.join("chain");
        write(&chain_path, 0o444, chain.as_bytes())?;

        debug!("writing single cert");
        let cert_path = path.join("cert");
        write(&cert_path, 0o444, cert.as_bytes())?;

        debug!("writing bundle");
        let bundle_path = path.join("bundle");
        write(&bundle_path, 0o440, bundle.as_bytes())?;

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

fn create(path: &Path, mode: u32) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(Error::from)
}

fn write(path: &Path, mode: u32, data: &[u8]) -> Result<()> {
    let mut f = create(path, mode)?;
    f.write_all(data)?;
    Ok(())
}

fn split_chain(fullchain: &str) -> Result<(String, String)> {
    let pems = pem::parse_many(fullchain).context("Failed to parse fullchain as pem")?;

    if pems.is_empty() {
        bail!("Input has no certificates");
    }

    let cert = pem::encode(&pems[0]);
    let chain = pem::encode_many(&pems[1..]);

    Ok((chain, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_none() {
        let r = split_chain("");
        assert!(r.is_err());
    }

    #[test]
    fn test_split_one() {
        let (chain, cert) = split_chain(
            "-----BEGIN CERTIFICATE-----
MIIE1DCCA7ygAwIBAgISA22Gkmt31e1mitao+ENL+sr3MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA0MjgyMzMxMjdaFw0y
MDA3MjcyMzMxMjdaMCUxIzAhBgNVBAMTGmNhY2hlLnJlYnVpbGRlci5menlsYWIu
bmV0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETyu5fNMOS/Lm/CwddSGEBH/XznHo
+nzPGVWxRDRl6UayntgPnTxBRi4HzUj91249mL0Q+/bYLWJdWueAJomi7CRVU3jo
E8oDVR6f528TRna2qoi0KTs8vJgMETy80yy7o4IChTCCAoEwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBREiBvysibRSVuw2Ur0qygxYaGtADAfBgNVHSMEGDAWgBSoSmpj
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMDsGA1UdEQQ0MDKCGmNh
Y2hlLnJlYnVpbGRlci5menlsYWIubmV0ghRyZWJ1aWxkZXIuZnp5bGFiLm5ldDBM
BgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIB
FhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUE
gfIA8AB1APCVpFnyANGCQBAtL5OIjq1L/h1H45nh0DSmsKiqjrJzAAABccNYerAA
AAQDAEYwRAIgP3HbNC75DEiLEE/TKhGw09fSWp/TewhRl/4XvmoxnWMCIE/3+yGf
gdi3bgjXhtspUqkKKcA/HLS7YXiwtu3hnc8SAHcAsh4FzIuizYogTodm+Su5iiUg
Z2va+nDnsklTLe+LkF4AAAFxw1h6owAABAMASDBGAiEAsQkiJ6UNE//GvhIyoJVs
Ah2ad7w+zPW2gVmYQFeVOJACIQDUhFc8FYzFDo3mIhHoY6+ODjLK4l6ruR28606D
X1WLbzANBgkqhkiG9w0BAQsFAAOCAQEAV/xkamOUFhtjyy6MPPBfT7nBYSBjTo7h
nlIuj5QZ5dHYM2eOZg77VOGpSgD5mlj0pqyspDMCkhsHVrmGFOcFKWgvwN5W6WF/
l7VHipzyxsPctUQK8pPRfOR8l2iMBj9+qpKmLx6v/BRN5ycj2giMuw6pbIoB3n6T
nXq0uZRfAm2kmQ64WusLvkvgpS61J0m70JI2mXdr+epeXwKdWcmnZJ4CCOiSYdv/
AxdDRttRGfpNyAxuMiyCccwXW2rNfc7EHQ7Myb7f3eE9cE6wLu/JLCCUotgafi08
aJ6TSPxS0YlSBhKYNbOUI7R8ZbjAJe/vI1IcYYhMaIW0kAzo4nxEmg==
-----END CERTIFICATE-----
",
        )
        .unwrap();
        assert_eq!(chain, "");
        assert_eq!(
            cert,
            "-----BEGIN CERTIFICATE-----\r\n\
MIIE1DCCA7ygAwIBAgISA22Gkmt31e1mitao+ENL+sr3MA0GCSqGSIb3DQEBCwUA\r\n\
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\r\n\
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA0MjgyMzMxMjdaFw0y\r\n\
MDA3MjcyMzMxMjdaMCUxIzAhBgNVBAMTGmNhY2hlLnJlYnVpbGRlci5menlsYWIu\r\n\
bmV0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETyu5fNMOS/Lm/CwddSGEBH/XznHo\r\n\
+nzPGVWxRDRl6UayntgPnTxBRi4HzUj91249mL0Q+/bYLWJdWueAJomi7CRVU3jo\r\n\
E8oDVR6f528TRna2qoi0KTs8vJgMETy80yy7o4IChTCCAoEwDgYDVR0PAQH/BAQD\r\n\
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA\r\n\
MB0GA1UdDgQWBBREiBvysibRSVuw2Ur0qygxYaGtADAfBgNVHSMEGDAWgBSoSmpj\r\n\
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0\r\n\
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0\r\n\
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMDsGA1UdEQQ0MDKCGmNh\r\n\
Y2hlLnJlYnVpbGRlci5menlsYWIubmV0ghRyZWJ1aWxkZXIuZnp5bGFiLm5ldDBM\r\n\
BgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIB\r\n\
FhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUE\r\n\
gfIA8AB1APCVpFnyANGCQBAtL5OIjq1L/h1H45nh0DSmsKiqjrJzAAABccNYerAA\r\n\
AAQDAEYwRAIgP3HbNC75DEiLEE/TKhGw09fSWp/TewhRl/4XvmoxnWMCIE/3+yGf\r\n\
gdi3bgjXhtspUqkKKcA/HLS7YXiwtu3hnc8SAHcAsh4FzIuizYogTodm+Su5iiUg\r\n\
Z2va+nDnsklTLe+LkF4AAAFxw1h6owAABAMASDBGAiEAsQkiJ6UNE//GvhIyoJVs\r\n\
Ah2ad7w+zPW2gVmYQFeVOJACIQDUhFc8FYzFDo3mIhHoY6+ODjLK4l6ruR28606D\r\n\
X1WLbzANBgkqhkiG9w0BAQsFAAOCAQEAV/xkamOUFhtjyy6MPPBfT7nBYSBjTo7h\r\n\
nlIuj5QZ5dHYM2eOZg77VOGpSgD5mlj0pqyspDMCkhsHVrmGFOcFKWgvwN5W6WF/\r\n\
l7VHipzyxsPctUQK8pPRfOR8l2iMBj9+qpKmLx6v/BRN5ycj2giMuw6pbIoB3n6T\r\n\
nXq0uZRfAm2kmQ64WusLvkvgpS61J0m70JI2mXdr+epeXwKdWcmnZJ4CCOiSYdv/\r\n\
AxdDRttRGfpNyAxuMiyCccwXW2rNfc7EHQ7Myb7f3eE9cE6wLu/JLCCUotgafi08\r\n\
aJ6TSPxS0YlSBhKYNbOUI7R8ZbjAJe/vI1IcYYhMaIW0kAzo4nxEmg==\r\n\
-----END CERTIFICATE-----\r\n"
        );
    }

    #[test]
    fn test_split_two() {
        let (chain, cert) = split_chain(
            "-----BEGIN CERTIFICATE-----
MIIE1DCCA7ygAwIBAgISA22Gkmt31e1mitao+ENL+sr3MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA0MjgyMzMxMjdaFw0y
MDA3MjcyMzMxMjdaMCUxIzAhBgNVBAMTGmNhY2hlLnJlYnVpbGRlci5menlsYWIu
bmV0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETyu5fNMOS/Lm/CwddSGEBH/XznHo
+nzPGVWxRDRl6UayntgPnTxBRi4HzUj91249mL0Q+/bYLWJdWueAJomi7CRVU3jo
E8oDVR6f528TRna2qoi0KTs8vJgMETy80yy7o4IChTCCAoEwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBREiBvysibRSVuw2Ur0qygxYaGtADAfBgNVHSMEGDAWgBSoSmpj
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMDsGA1UdEQQ0MDKCGmNh
Y2hlLnJlYnVpbGRlci5menlsYWIubmV0ghRyZWJ1aWxkZXIuZnp5bGFiLm5ldDBM
BgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIB
FhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUE
gfIA8AB1APCVpFnyANGCQBAtL5OIjq1L/h1H45nh0DSmsKiqjrJzAAABccNYerAA
AAQDAEYwRAIgP3HbNC75DEiLEE/TKhGw09fSWp/TewhRl/4XvmoxnWMCIE/3+yGf
gdi3bgjXhtspUqkKKcA/HLS7YXiwtu3hnc8SAHcAsh4FzIuizYogTodm+Su5iiUg
Z2va+nDnsklTLe+LkF4AAAFxw1h6owAABAMASDBGAiEAsQkiJ6UNE//GvhIyoJVs
Ah2ad7w+zPW2gVmYQFeVOJACIQDUhFc8FYzFDo3mIhHoY6+ODjLK4l6ruR28606D
X1WLbzANBgkqhkiG9w0BAQsFAAOCAQEAV/xkamOUFhtjyy6MPPBfT7nBYSBjTo7h
nlIuj5QZ5dHYM2eOZg77VOGpSgD5mlj0pqyspDMCkhsHVrmGFOcFKWgvwN5W6WF/
l7VHipzyxsPctUQK8pPRfOR8l2iMBj9+qpKmLx6v/BRN5ycj2giMuw6pbIoB3n6T
nXq0uZRfAm2kmQ64WusLvkvgpS61J0m70JI2mXdr+epeXwKdWcmnZJ4CCOiSYdv/
AxdDRttRGfpNyAxuMiyCccwXW2rNfc7EHQ7Myb7f3eE9cE6wLu/JLCCUotgafi08
aJ6TSPxS0YlSBhKYNbOUI7R8ZbjAJe/vI1IcYYhMaIW0kAzo4nxEmg==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
",
        )
        .unwrap();
        assert_eq!(
            chain,
            "-----BEGIN CERTIFICATE-----\r\n\
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\r\n\
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n\
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\r\n\
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\r\n\
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n\
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\r\n\
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\r\n\
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\r\n\
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\r\n\
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\r\n\
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\r\n\
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\r\n\
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\r\n\
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\r\n\
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\r\n\
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\r\n\
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\r\n\
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\r\n\
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\r\n\
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\r\n\
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\r\n\
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\r\n\
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\r\n\
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\r\n\
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\r\n\
-----END CERTIFICATE-----\r\n"
        );
        assert_eq!(
            cert,
            "-----BEGIN CERTIFICATE-----\r\n\
MIIE1DCCA7ygAwIBAgISA22Gkmt31e1mitao+ENL+sr3MA0GCSqGSIb3DQEBCwUA\r\n\
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\r\n\
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA0MjgyMzMxMjdaFw0y\r\n\
MDA3MjcyMzMxMjdaMCUxIzAhBgNVBAMTGmNhY2hlLnJlYnVpbGRlci5menlsYWIu\r\n\
bmV0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETyu5fNMOS/Lm/CwddSGEBH/XznHo\r\n\
+nzPGVWxRDRl6UayntgPnTxBRi4HzUj91249mL0Q+/bYLWJdWueAJomi7CRVU3jo\r\n\
E8oDVR6f528TRna2qoi0KTs8vJgMETy80yy7o4IChTCCAoEwDgYDVR0PAQH/BAQD\r\n\
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA\r\n\
MB0GA1UdDgQWBBREiBvysibRSVuw2Ur0qygxYaGtADAfBgNVHSMEGDAWgBSoSmpj\r\n\
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0\r\n\
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0\r\n\
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMDsGA1UdEQQ0MDKCGmNh\r\n\
Y2hlLnJlYnVpbGRlci5menlsYWIubmV0ghRyZWJ1aWxkZXIuZnp5bGFiLm5ldDBM\r\n\
BgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIB\r\n\
FhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUE\r\n\
gfIA8AB1APCVpFnyANGCQBAtL5OIjq1L/h1H45nh0DSmsKiqjrJzAAABccNYerAA\r\n\
AAQDAEYwRAIgP3HbNC75DEiLEE/TKhGw09fSWp/TewhRl/4XvmoxnWMCIE/3+yGf\r\n\
gdi3bgjXhtspUqkKKcA/HLS7YXiwtu3hnc8SAHcAsh4FzIuizYogTodm+Su5iiUg\r\n\
Z2va+nDnsklTLe+LkF4AAAFxw1h6owAABAMASDBGAiEAsQkiJ6UNE//GvhIyoJVs\r\n\
Ah2ad7w+zPW2gVmYQFeVOJACIQDUhFc8FYzFDo3mIhHoY6+ODjLK4l6ruR28606D\r\n\
X1WLbzANBgkqhkiG9w0BAQsFAAOCAQEAV/xkamOUFhtjyy6MPPBfT7nBYSBjTo7h\r\n\
nlIuj5QZ5dHYM2eOZg77VOGpSgD5mlj0pqyspDMCkhsHVrmGFOcFKWgvwN5W6WF/\r\n\
l7VHipzyxsPctUQK8pPRfOR8l2iMBj9+qpKmLx6v/BRN5ycj2giMuw6pbIoB3n6T\r\n\
nXq0uZRfAm2kmQ64WusLvkvgpS61J0m70JI2mXdr+epeXwKdWcmnZJ4CCOiSYdv/\r\n\
AxdDRttRGfpNyAxuMiyCccwXW2rNfc7EHQ7Myb7f3eE9cE6wLu/JLCCUotgafi08\r\n\
aJ6TSPxS0YlSBhKYNbOUI7R8ZbjAJe/vI1IcYYhMaIW0kAzo4nxEmg==\r\n\
-----END CERTIFICATE-----\r\n"
        );
    }

    #[test]
    fn test_split_three() {
        let (chain, cert) = split_chain(
            "-----BEGIN CERTIFICATE-----
MIIE1DCCA7ygAwIBAgISA22Gkmt31e1mitao+ENL+sr3MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA0MjgyMzMxMjdaFw0y
MDA3MjcyMzMxMjdaMCUxIzAhBgNVBAMTGmNhY2hlLnJlYnVpbGRlci5menlsYWIu
bmV0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETyu5fNMOS/Lm/CwddSGEBH/XznHo
+nzPGVWxRDRl6UayntgPnTxBRi4HzUj91249mL0Q+/bYLWJdWueAJomi7CRVU3jo
E8oDVR6f528TRna2qoi0KTs8vJgMETy80yy7o4IChTCCAoEwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBREiBvysibRSVuw2Ur0qygxYaGtADAfBgNVHSMEGDAWgBSoSmpj
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMDsGA1UdEQQ0MDKCGmNh
Y2hlLnJlYnVpbGRlci5menlsYWIubmV0ghRyZWJ1aWxkZXIuZnp5bGFiLm5ldDBM
BgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIB
FhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUE
gfIA8AB1APCVpFnyANGCQBAtL5OIjq1L/h1H45nh0DSmsKiqjrJzAAABccNYerAA
AAQDAEYwRAIgP3HbNC75DEiLEE/TKhGw09fSWp/TewhRl/4XvmoxnWMCIE/3+yGf
gdi3bgjXhtspUqkKKcA/HLS7YXiwtu3hnc8SAHcAsh4FzIuizYogTodm+Su5iiUg
Z2va+nDnsklTLe+LkF4AAAFxw1h6owAABAMASDBGAiEAsQkiJ6UNE//GvhIyoJVs
Ah2ad7w+zPW2gVmYQFeVOJACIQDUhFc8FYzFDo3mIhHoY6+ODjLK4l6ruR28606D
X1WLbzANBgkqhkiG9w0BAQsFAAOCAQEAV/xkamOUFhtjyy6MPPBfT7nBYSBjTo7h
nlIuj5QZ5dHYM2eOZg77VOGpSgD5mlj0pqyspDMCkhsHVrmGFOcFKWgvwN5W6WF/
l7VHipzyxsPctUQK8pPRfOR8l2iMBj9+qpKmLx6v/BRN5ycj2giMuw6pbIoB3n6T
nXq0uZRfAm2kmQ64WusLvkvgpS61J0m70JI2mXdr+epeXwKdWcmnZJ4CCOiSYdv/
AxdDRttRGfpNyAxuMiyCccwXW2rNfc7EHQ7Myb7f3eE9cE6wLu/JLCCUotgafi08
aJ6TSPxS0YlSBhKYNbOUI7R8ZbjAJe/vI1IcYYhMaIW0kAzo4nxEmg==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
",
        )
        .unwrap();

        assert_eq!(
            chain,
            "-----BEGIN CERTIFICATE-----\r\n\
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\r\n\
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n\
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\r\n\
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\r\n\
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n\
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\r\n\
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\r\n\
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\r\n\
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\r\n\
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\r\n\
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\r\n\
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\r\n\
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\r\n\
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\r\n\
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\r\n\
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\r\n\
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\r\n\
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\r\n\
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\r\n\
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\r\n\
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\r\n\
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\r\n\
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\r\n\
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\r\n\
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\r\n\
-----END CERTIFICATE-----\r\n\
\r\n\
-----BEGIN CERTIFICATE-----\r\n\
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\r\n\
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n\
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\r\n\
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\r\n\
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n\
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\r\n\
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\r\n\
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\r\n\
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\r\n\
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\r\n\
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\r\n\
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\r\n\
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\r\n\
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\r\n\
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\r\n\
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\r\n\
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\r\n\
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\r\n\
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\r\n\
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\r\n\
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\r\n\
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\r\n\
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\r\n\
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\r\n\
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\r\n\
-----END CERTIFICATE-----\r\n"
        );
        assert_eq!(
            cert,
            "-----BEGIN CERTIFICATE-----\r\n\
MIIE1DCCA7ygAwIBAgISA22Gkmt31e1mitao+ENL+sr3MA0GCSqGSIb3DQEBCwUA\r\n\
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\r\n\
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA0MjgyMzMxMjdaFw0y\r\n\
MDA3MjcyMzMxMjdaMCUxIzAhBgNVBAMTGmNhY2hlLnJlYnVpbGRlci5menlsYWIu\r\n\
bmV0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETyu5fNMOS/Lm/CwddSGEBH/XznHo\r\n\
+nzPGVWxRDRl6UayntgPnTxBRi4HzUj91249mL0Q+/bYLWJdWueAJomi7CRVU3jo\r\n\
E8oDVR6f528TRna2qoi0KTs8vJgMETy80yy7o4IChTCCAoEwDgYDVR0PAQH/BAQD\r\n\
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA\r\n\
MB0GA1UdDgQWBBREiBvysibRSVuw2Ur0qygxYaGtADAfBgNVHSMEGDAWgBSoSmpj\r\n\
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0\r\n\
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0\r\n\
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMDsGA1UdEQQ0MDKCGmNh\r\n\
Y2hlLnJlYnVpbGRlci5menlsYWIubmV0ghRyZWJ1aWxkZXIuZnp5bGFiLm5ldDBM\r\n\
BgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIB\r\n\
FhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUE\r\n\
gfIA8AB1APCVpFnyANGCQBAtL5OIjq1L/h1H45nh0DSmsKiqjrJzAAABccNYerAA\r\n\
AAQDAEYwRAIgP3HbNC75DEiLEE/TKhGw09fSWp/TewhRl/4XvmoxnWMCIE/3+yGf\r\n\
gdi3bgjXhtspUqkKKcA/HLS7YXiwtu3hnc8SAHcAsh4FzIuizYogTodm+Su5iiUg\r\n\
Z2va+nDnsklTLe+LkF4AAAFxw1h6owAABAMASDBGAiEAsQkiJ6UNE//GvhIyoJVs\r\n\
Ah2ad7w+zPW2gVmYQFeVOJACIQDUhFc8FYzFDo3mIhHoY6+ODjLK4l6ruR28606D\r\n\
X1WLbzANBgkqhkiG9w0BAQsFAAOCAQEAV/xkamOUFhtjyy6MPPBfT7nBYSBjTo7h\r\n\
nlIuj5QZ5dHYM2eOZg77VOGpSgD5mlj0pqyspDMCkhsHVrmGFOcFKWgvwN5W6WF/\r\n\
l7VHipzyxsPctUQK8pPRfOR8l2iMBj9+qpKmLx6v/BRN5ycj2giMuw6pbIoB3n6T\r\n\
nXq0uZRfAm2kmQ64WusLvkvgpS61J0m70JI2mXdr+epeXwKdWcmnZJ4CCOiSYdv/\r\n\
AxdDRttRGfpNyAxuMiyCccwXW2rNfc7EHQ7Myb7f3eE9cE6wLu/JLCCUotgafi08\r\n\
aJ6TSPxS0YlSBhKYNbOUI7R8ZbjAJe/vI1IcYYhMaIW0kAzo4nxEmg==\r\n\
-----END CERTIFICATE-----\r\n"
        );
    }
}
