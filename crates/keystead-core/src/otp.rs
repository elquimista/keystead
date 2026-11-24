//! One-time codes: the time-based codes (TOTP, RFC 6238) that sites ask for as a second
//! factor. A login keeps its setup in its details as an `otpauth://totp/…` link, the way
//! sites hand it out in a QR code; codes come from that link and the clock. The algorithm
//! is the `totp-rs` crate's.

use std::fmt;

use totp_rs::{TOTP, TotpUrlError};

use crate::Error;

/// A code, and how long it lasts.
#[derive(Clone, PartialEq, Eq)]
pub struct OneTimeCode {
    pub code: String,
    /// Seconds each code lasts, usually 30.
    pub period: u64,
    /// Seconds this one has left, from 1 to `period`.
    pub remaining: u64,
}

impl fmt::Debug for OneTimeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OneTimeCode(redacted, {}s left)", self.remaining)
    }
}

/// The link to keep for what someone pasted: an `otpauth://totp/…` link (what a site's QR
/// code holds), or the setup key sites show for typing in instead, in base32
/// ("JBSW Y3DP EHPK 3PXP"; spaces, dashes and case don't matter). Fails unless it makes
/// codes. Errors never repeat the secret.
pub fn normalize(text: &str) -> Result<String, Error> {
    let text = text.trim();
    let link = if text
        .get(..10)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("otpauth://"))
    {
        text.to_owned()
    } else {
        let key: String = text
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .trim_end_matches('=')
            .to_ascii_uppercase();
        if key.is_empty() {
            return Err(invalid("it's empty"));
        }
        format!("otpauth://totp/?secret={key}")
    };
    parse(&link)?;
    Ok(link)
}

/// The code for `link` at `time` (seconds since 1970, UTC).
pub fn code_at(link: &str, time: u64) -> Result<OneTimeCode, Error> {
    let totp = parse(link)?;
    Ok(OneTimeCode {
        code: totp.generate(time),
        period: totp.step,
        remaining: totp.step - time % totp.step,
    })
}

/// Who the codes are for, as the link names them: "GitHub (octocat)", "GitHub", "octocat",
/// or empty for a bare setup key.
pub fn label(link: &str) -> Result<String, Error> {
    let totp = parse(link)?;
    let account = totp.account_name.trim();
    Ok(match totp.issuer.as_deref().map(str::trim) {
        Some(issuer) if !issuer.is_empty() && !account.is_empty() && issuer != account => {
            format!("{issuer} ({account})")
        }
        Some(issuer) if !issuer.is_empty() => issuer.to_owned(),
        _ => account.to_owned(),
    })
}

fn parse(link: &str) -> Result<TOTP, Error> {
    // Unchecked: many sites still hand out 80-bit secrets, below RFC 4226's 128.
    let totp = TOTP::from_url_unchecked(link).map_err(|error| {
        invalid(match error {
            TotpUrlError::Scheme(_) => "it isn't an otpauth:// link",
            TotpUrlError::Host(host) if host.eq_ignore_ascii_case("hotp") => {
                "it's for counter-based codes (HOTP); Keystead does time-based ones"
            }
            TotpUrlError::Host(_) => "it isn't for time-based codes (otpauth://totp/…)",
            TotpUrlError::Secret(_) | TotpUrlError::SecretSize(_) => {
                "its secret isn't valid base32"
            }
            TotpUrlError::Algorithm(_) => "its algorithm isn't SHA1, SHA256 or SHA512",
            TotpUrlError::Digits(_) | TotpUrlError::DigitsNumber(_) => {
                "its number of digits isn't valid"
            }
            TotpUrlError::Step(_) => "its period isn't valid",
            _ => "it isn't a valid otpauth:// link",
        })
    })?;
    if totp.secret.is_empty() {
        return Err(invalid("it has no secret"));
    }
    if !(6..=8).contains(&totp.digits) {
        return Err(invalid("codes must have 6 to 8 digits"));
    }
    if totp.step == 0 {
        return Err(invalid("its period isn't valid"));
    }
    Ok(totp)
}

fn invalid(reason: &str) -> Error {
    Error::OneTimeCode(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's test secret ("12345678901234567890") and its SHA1 vectors.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn codes_match_the_rfc_test_vectors() {
        let link = normalize(&format!(
            "otpauth://totp/Example:alice?secret={RFC_SECRET}&digits=8"
        ))
        .unwrap();
        for (time, code) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ] {
            assert_eq!(code_at(&link, time).unwrap().code, code, "at {time}");
        }
        let code = code_at(&link, 59).unwrap();
        assert_eq!((code.period, code.remaining), (30, 1));
        assert_eq!(code_at(&link, 60).unwrap().remaining, 30);
    }

    #[test]
    fn setup_keys_as_sites_show_them() {
        // Spaces, lower case and an 80-bit secret, as many sites still use.
        let link = normalize("  jbsw y3dp ehpk 3pxp ").unwrap();
        assert_eq!(link, "otpauth://totp/?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(code_at(&link, 0).unwrap().code.len(), 6);
        assert_eq!(label(&link).unwrap(), "");
    }

    #[test]
    fn labels_and_bad_input() {
        let link = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        assert_eq!(normalize(link).unwrap(), link);
        assert_eq!(label(link).unwrap(), "GitHub (octocat)");

        for (text, reason) in [
            ("", "empty"),
            ("not base32!", "base32"),
            (
                "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
                "counter-based",
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
                "6 to 8",
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
                "algorithm",
            ),
        ] {
            let error = normalize(text).unwrap_err().to_string();
            assert!(error.contains(reason), "{text:?}: {error}");
            assert!(
                !error.contains("JBSWY3DPEHPK3PXP"),
                "the secret leaked: {error}"
            );
        }
    }
}
