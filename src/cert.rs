use crate::errors::*;

#[derive(Debug)]
pub struct CertInfo {
    pub not_before: String,
    pub expires: time::OffsetDateTime,
}

impl CertInfo {
    pub fn from_pem(certificate: &[u8]) -> Result<CertInfo> {
        let pem = pem::parse(certificate).context("Failed to parse pem file")?;

        let (_, certificate) = x509_parser::parse_x509_certificate(pem.contents())
            .context("Failed to parse certificate")?;
        let validity = certificate.validity();

        Ok(CertInfo {
            not_before: validity.not_before.to_string(),
            expires: validity.not_after.to_datetime(),
        })
    }

    pub fn days_left(&self) -> i64 {
        let dur = self.expires - time::OffsetDateTime::now_utc();
        dur.whole_days()
    }
}
