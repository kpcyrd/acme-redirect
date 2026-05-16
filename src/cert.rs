use crate::errors::*;

#[derive(Debug, PartialEq)]
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

    fn days_left_from(&self, now: time::OffsetDateTime) -> i64 {
        let dur = self.expires - now;
        dur.whole_days()
    }

    pub fn days_left(&self) -> i64 {
        self.days_left_from(time::OffsetDateTime::now_utc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Month;

    fn datetime(
        year: i32,
        month: Month,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> time::OffsetDateTime {
        time::OffsetDateTime::new_utc(
            time::Date::from_calendar_date(year, month, day).unwrap(),
            time::Time::from_hms(hour, minute, second).unwrap(),
        )
    }

    #[test]
    fn test_parse_sh4d0wup_pem() {
        let cert = r#"
-----BEGIN CERTIFICATE-----
MIIBXDCCAQKgAwIBAgIUZtwYFW2Db5tjmbrDav1DzGwb6LEwCgYIKoZIzj0EAwIw
LTErMCkGA1UEAwwiZmxvd2VycyBhcmUgYmxvb21pbmcgaW4gYW50YXJjdGljYTAg
Fw03NTAxMDEwMDAwMDBaGA80MDk2MDEwMTAwMDAwMFowLTErMCkGA1UEAwwiZmxv
d2VycyBhcmUgYmxvb21pbmcgaW4gYW50YXJjdGljYTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABNbW5jkPKJWJDAy8+SYtM/9LXETga3KmGYyyUP71nNehbLsQjbyd
bn6+BWsCwbIuvTTH/FcbzRFq1v0L9PqZuocwCgYIKoZIzj0EAwIDSAAwRQIgWJrx
gIXowJ9kQEp/x8JLbieAQsyLebruy7FNCfl5OQACIQD9I0/iP7JasLIXjM6/BwJ0
m9Iy/v8ftvQCp2l/qlk1/A==
-----END CERTIFICATE-----
"#;
        let cert = CertInfo::from_pem(cert.as_bytes()).unwrap();
        assert_eq!(
            cert,
            CertInfo {
                not_before: "Jan  1 00:00:00 1975 +00:00".to_string(),
                expires: datetime(4096, Month::January, 1, 0, 0, 0),
            }
        );
        assert_eq!(
            cert.days_left_from(datetime(2026, Month::May, 15, 16, 20, 0)),
            755917
        );
    }

    #[test]
    fn test_letsencrypt_pem() {
        let cert = r#"

        -----BEGIN CERTIFICATE-----
MIIEQjCCA8igAwIBAgISBRirJMSMrHnDgH6LMSv04ZwQMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
NzAeFw0yNjA1MDcxNjE0MzdaFw0yNjA4MDUxNjE0MzZaMBoxGDAWBgNVBAMTD2xl
dHNlbmNyeXB0Lm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABES9iPUkeXDT
TfBhAuKX4XFyRcGaBBjny62Mt9qT0p4tD16QxO5nMfmGGUK5XEW9JiHI+1r/V3r/
ugNSSmddGkOjggLUMIIC0DAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUYnUD21il8jofbVRVXikFWNEF
nRAwHwYDVR0jBBgwFoAUrkie3IcdRKBv2qLlYHQEeMKcAIAwMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8vZTcuaS5sZW5jci5vcmcvMIHTBgNVHREE
gcswgciCEmNwLmxldHNlbmNyeXB0Lm9yZ4IaY3Aucm9vdC14MS5sZXRzZW5jcnlw
dC5vcmeCE2Nwcy5sZXRzZW5jcnlwdC5vcmeCG2Nwcy5yb290LXgxLmxldHNlbmNy
eXB0Lm9yZ4IJbGVuY3Iub3Jngg9sZXRzZW5jcnlwdC5jb22CD2xldHNlbmNyeXB0
Lm9yZ4INd3d3LmxlbmNyLm9yZ4ITd3d3LmxldHNlbmNyeXB0LmNvbYITd3d3Lmxl
dHNlbmNyeXB0Lm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATAtBgNVHR8EJjAkMCKg
IKAehhxodHRwOi8vZTcuYy5sZW5jci5vcmcvMTcuY3JsMIIBCwYKKwYBBAHWeQIE
AgSB/ASB+QD3AH0ARq+GPTs+5Z+ld96oJF02sNntIqIj9GF3QSKUUu6VUF8AAAGe
A23MWgAIAAAFAAX0LC0EAwBGMEQCIHCnN2ETVwQIGlyamkqh2bIJ4IcSbwcN97Mv
D3lSvzx0AiA2bzpKNQ+4dWvWQTJ5fivsSGn5Cm/zUar3eewHuG+KngB2AK9niDtX
sE7dj6bZfvYuqOuBCsdxYPAkXlXWDC/nhYc6AAABngNtzRQAAAQDAEcwRQIhALki
D0CP+jGP7vYPSaocL0EOC739MbZhzKsL+UtjRbyCAiB2d5oklh219kcb755iT/63
1uf2DuZsdD0DyuH1yi5f6TAKBggqhkjOPQQDAwNoADBlAjAo8jdjP7B6WNRfjXvK
s0TPy5NBj5WsRIjLuirPnXdJlPe84a7xWGL4ErUSXLoe1qECMQDgE+ylhhKiSjW6
DZSVIDNQ9IZBVfUfHHpoTgqF8qxrVB8a0/PSz7K5TDkDQP/Bfec=
-----END CERTIFICATE-----
"#;
        let cert = CertInfo::from_pem(cert.as_bytes()).unwrap();
        assert_eq!(
            cert,
            CertInfo {
                not_before: "May  7 16:14:37 2026 +00:00".to_string(),
                expires: datetime(2026, Month::August, 5, 16, 14, 36),
            }
        );
        assert_eq!(
            cert.days_left_from(datetime(2026, Month::May, 15, 16, 00, 0)),
            82
        );
        assert_eq!(
            cert.days_left_from(datetime(2026, Month::May, 15, 16, 20, 0)),
            81
        );
    }
}
