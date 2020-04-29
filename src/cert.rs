use crate::errors::*;
use openssl::x509::X509;

#[derive(Debug)]
pub struct CertInfo {
    pub not_before: String,
    pub expires: time::Tm,
}

impl CertInfo {
    pub fn from_pem(s: &[u8]) -> Result<CertInfo> {
        // load as x509
        let x509 = X509::from_pem(s).context("Failed to parse pem file")?;

        let not_before = x509.not_before().to_string();

        // convert asn1 time to Tm
        let not_after = x509.not_after().to_string();
        // Display trait produces this format, which is kinda dumb.
        // Apr 19 08:48:46 2019 GMT
        let expires = parse_date(&not_after);
        // let dur = expires - time::now();

        // dur.num_days()

        Ok(CertInfo {
            not_before,
            expires,
        })
    }

    pub fn days_left(&self) -> i64 {
        let dur = self.expires - time::now();
        dur.num_days()
    }
}

fn parse_date(s: &str) -> time::Tm {
    time::strptime(s, "%h %e %H:%M:%S %Y %Z").expect("strptime")
}
