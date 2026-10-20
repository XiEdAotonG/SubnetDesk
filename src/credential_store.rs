//! Platform backed storage for LAN access secrets.
//!
//! Passwords never live in the JSON config: desktop targets delegate to the
//! operating system credential store, Android encrypts with a non-exportable
//! Android Keystore key, and every other target reports the feature as
//! unsupported instead of falling back to plaintext.

use hbb_common::ResultType;
use zeroize::Zeroizing;

pub(crate) const LAN_CREDENTIAL_SERVICE: &str = "com.zibochen.SubnetDesk.LANCredentials";
pub(crate) const LAN_IDENTITY_SERVICE: &str = "com.zibochen.SubnetDesk.LANIdentities";

/// Combine a service namespace and an account into one storage key.
#[cfg(any(target_os = "android", test))]
fn entry_key(service: &str, account: &str) -> String {
    format!("{service}|{account}")
}

pub(crate) fn is_supported() -> bool {
    backend::is_supported()
}

pub(crate) fn store(service: &str, account: &str, secret: &[u8]) -> ResultType<()> {
    backend::store(service, account, secret)
}

pub(crate) fn load(service: &str, account: &str) -> ResultType<Option<Zeroizing<Vec<u8>>>> {
    backend::load(service, account)
}

pub(crate) fn delete(service: &str, account: &str) -> ResultType<()> {
    backend::delete(service, account)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod backend {
    use hbb_common::{anyhow::anyhow, ResultType};
    use zeroize::{Zeroize, Zeroizing};

    pub(super) fn is_supported() -> bool {
        true
    }

    pub(super) fn store(service: &str, account: &str, secret: &[u8]) -> ResultType<()> {
        let secret = std::str::from_utf8(secret)
            .map_err(|_| anyhow!("The credential is not valid UTF-8"))?;
        keyring::Entry::new(service, account)
            .map_err(|err| anyhow!("Failed to open the operating system credential store: {err}"))?
            .set_password(secret)
            .map_err(|err| anyhow!("Failed to save the credential: {err}"))
    }

    pub(super) fn load(service: &str, account: &str) -> ResultType<Option<Zeroizing<Vec<u8>>>> {
        let entry = keyring::Entry::new(service, account).map_err(|err| {
            anyhow!("Failed to open the operating system credential store: {err}")
        })?;
        let mut text = match entry.get_password() {
            Ok(text) => text,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(err) => return Err(anyhow!("Failed to read the credential: {err}")),
        };
        let secret = Zeroizing::new(text.as_bytes().to_vec());
        text.zeroize();
        Ok(Some(secret))
    }

    pub(super) fn delete(service: &str, account: &str) -> ResultType<()> {
        let entry = keyring::Entry::new(service, account).map_err(|err| {
            anyhow!("Failed to open the operating system credential store: {err}")
        })?;
        match entry.delete_password() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(anyhow!("Failed to delete the credential: {err}")),
        }
    }
}

#[cfg(target_os = "android")]
mod backend {
    use super::entry_key;
    use hbb_common::ResultType;
    use zeroize::Zeroizing;

    pub(super) fn is_supported() -> bool {
        true
    }

    pub(super) fn store(service: &str, account: &str, secret: &[u8]) -> ResultType<()> {
        crate::android_secure_store::put(&entry_key(service, account), secret)
    }

    pub(super) fn load(service: &str, account: &str) -> ResultType<Option<Zeroizing<Vec<u8>>>> {
        crate::android_secure_store::get(&entry_key(service, account))
    }

    pub(super) fn delete(service: &str, account: &str) -> ResultType<()> {
        crate::android_secure_store::remove(&entry_key(service, account))
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "android"
)))]
mod backend {
    use hbb_common::{bail, ResultType};
    use zeroize::Zeroizing;

    pub(super) fn is_supported() -> bool {
        false
    }

    pub(super) fn store(_service: &str, _account: &str, _secret: &[u8]) -> ResultType<()> {
        bail!("Saving LAN passwords is not supported on this platform")
    }

    pub(super) fn load(_service: &str, _account: &str) -> ResultType<Option<Zeroizing<Vec<u8>>>> {
        Ok(None)
    }

    pub(super) fn delete(_service: &str, _account: &str) -> ResultType<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::entry_key;

    #[test]
    fn entry_key_is_namespaced_and_unambiguous() {
        assert_eq!(entry_key("service", "account"), "service|account");
        assert_ne!(entry_key("a", "b|c"), entry_key("a|b", "c"));
    }
}
