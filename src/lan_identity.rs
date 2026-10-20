use hbb_common::{
    anyhow::{anyhow, bail},
    config::{LanIdentity, LocalConfig},
    lan::{validate_password, validate_username},
    log, ResultType,
};
use serde::Serialize;
use uuid::Uuid;

const MAX_IDENTITY_NAME_LEN: usize = 64;

#[derive(Debug, Serialize)]
pub struct LanIdentitySummary {
    pub id: String,
    pub name: String,
    pub username: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub is_default: bool,
}

pub struct ResolvedLanIdentity {
    pub id: String,
    pub username: String,
    pub password: Vec<u8>,
}

fn validate_identity_name(name: &str) -> ResultType<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Identity name is required");
    }
    if name.len() > MAX_IDENTITY_NAME_LEN {
        bail!("Identity name is too long");
    }
    if name.chars().any(char::is_control) {
        bail!("Identity name contains control characters");
    }
    Ok(name.to_owned())
}

fn validate_identity_id(identity_id: &str) -> ResultType<String> {
    let identity_id = Uuid::parse_str(identity_id)
        .map_err(|_| anyhow!("Invalid LAN identity ID"))?
        .to_string();
    Ok(identity_id)
}

fn ensure_unique_name(name: &str, excluding_id: Option<&str>) -> ResultType<()> {
    if LocalConfig::lan_identity_name_exists(name, excluding_id) {
        bail!("An identity with this name already exists");
    }
    Ok(())
}

pub fn list() -> Vec<LanIdentitySummary> {
    let default_id = LocalConfig::get_default_lan_identity_id();
    LocalConfig::get_lan_identities()
        .into_iter()
        .map(|identity| LanIdentitySummary {
            is_default: identity.id == default_id,
            id: identity.id,
            name: identity.name,
            username: identity.username,
            created_at: identity.created_at,
            updated_at: identity.updated_at,
        })
        .collect()
}

pub fn create(
    name: &str,
    username: &str,
    password: &str,
    make_default: bool,
) -> ResultType<String> {
    let name = validate_identity_name(name)?;
    let username = validate_username(username)?;
    validate_password(password.as_bytes())?;
    ensure_unique_name(&name, None)?;
    let identity_id = Uuid::new_v4().to_string();

    crate::credential_store::store(
        crate::credential_store::LAN_IDENTITY_SERVICE,
        &identity_id,
        password.as_bytes(),
    )
    .map_err(|err| anyhow!("Failed to save the LAN identity password: {err}"))?;

    let now = hbb_common::get_time();
    LocalConfig::store_lan_identity(LanIdentity {
        id: identity_id.clone(),
        name,
        username,
        created_at: now,
        updated_at: now,
    });
    if make_default {
        LocalConfig::set_default_lan_identity_id(&identity_id)?;
    }
    Ok(identity_id)
}

pub fn update(
    identity_id: &str,
    name: &str,
    username: &str,
    password: Option<&str>,
    make_default: bool,
) -> ResultType<()> {
    let identity_id = validate_identity_id(identity_id)?;
    let name = validate_identity_name(name)?;
    let username = validate_username(username)?;
    ensure_unique_name(&name, Some(&identity_id))?;
    let mut identity = LocalConfig::get_lan_identity(&identity_id)
        .ok_or_else(|| anyhow!("LAN identity does not exist"))?;

    if let Some(password) = password {
        validate_password(password.as_bytes())?;
        crate::credential_store::store(
            crate::credential_store::LAN_IDENTITY_SERVICE,
            &identity_id,
            password.as_bytes(),
        )
        .map_err(|err| anyhow!("Failed to update the LAN identity password: {err}"))?;
    }

    identity.name = name;
    identity.username = username;
    identity.updated_at = hbb_common::get_time();
    LocalConfig::store_lan_identity(identity);
    if make_default {
        LocalConfig::set_default_lan_identity_id(&identity_id)?;
    } else if LocalConfig::get_default_lan_identity_id() == identity_id {
        LocalConfig::set_default_lan_identity_id("")?;
    }
    Ok(())
}

pub fn delete(identity_id: &str) -> ResultType<()> {
    let identity_id = validate_identity_id(identity_id)?;
    if LocalConfig::get_lan_identity(&identity_id).is_none() {
        bail!("LAN identity does not exist");
    }

    crate::credential_store::delete(
        crate::credential_store::LAN_IDENTITY_SERVICE,
        &identity_id,
    )
    .map_err(|err| anyhow!("Failed to delete the LAN identity password: {err}"))?;

    LocalConfig::remove_lan_identity(&identity_id);
    Ok(())
}

pub fn set_default(identity_id: &str) -> ResultType<()> {
    if identity_id.is_empty() {
        return LocalConfig::set_default_lan_identity_id("");
    }
    let identity_id = validate_identity_id(identity_id)?;
    LocalConfig::set_default_lan_identity_id(&identity_id)
}

pub fn bind(fingerprint: &str, identity_id: &str) -> ResultType<()> {
    if identity_id.is_empty() {
        return LocalConfig::bind_lan_identity(fingerprint, "");
    }
    let identity_id = validate_identity_id(identity_id)?;
    LocalConfig::bind_lan_identity(fingerprint, &identity_id)
}

pub fn bound_identity_id(fingerprint: &str) -> String {
    LocalConfig::get_bound_lan_identity_id(fingerprint)
}

pub fn resolved_identity_id(fingerprint: &str) -> String {
    LocalConfig::resolve_lan_identity_id(fingerprint)
}

pub fn load(identity_id: &str) -> ResultType<ResolvedLanIdentity> {
    let identity_id = validate_identity_id(identity_id)?;
    let identity = LocalConfig::get_lan_identity(&identity_id)
        .ok_or_else(|| anyhow!("LAN identity does not exist"))?;

    let password = crate::credential_store::load(
        crate::credential_store::LAN_IDENTITY_SERVICE,
        &identity_id,
    )
    .map_err(|err| anyhow!("Failed to read the LAN identity password: {err}"))?
    .ok_or_else(|| anyhow!("LAN identity password is missing"))?;
    validate_password(password.as_slice())?;
    Ok(ResolvedLanIdentity {
        id: identity_id,
        username: identity.username,
        password: password.to_vec(),
    })
}

pub fn load_for_fingerprint(fingerprint: &str) -> ResultType<Option<ResolvedLanIdentity>> {
    let identity_id = resolved_identity_id(fingerprint);
    if identity_id.is_empty() {
        Ok(None)
    } else {
        load(&identity_id).map(Some)
    }
}

pub fn has_legacy_credential(fingerprint: &str) -> bool {
    crate::client::load_remembered_lan_credential_for_fingerprint(fingerprint).is_some()
}

pub fn import_legacy_credential(
    fingerprint: &str,
    name: &str,
    make_default: bool,
) -> ResultType<String> {
    let (username, password) =
        crate::client::load_remembered_lan_credential_for_fingerprint(fingerprint)
            .ok_or_else(|| anyhow!("No remembered credential exists for this device"))?;
    let password_text = std::str::from_utf8(password.as_slice())
        .map_err(|_| anyhow!("Remembered LAN password is not valid UTF-8"))?;
    let identity_id = create(name, &username, password_text, make_default)?;
    if let Err(err) = bind(fingerprint, &identity_id) {
        if let Err(delete_err) = delete(&identity_id) {
            log::error!(
                "Failed to roll back imported LAN identity after binding failed: {delete_err}"
            );
        }
        return Err(err);
    }
    crate::client::clear_remembered_lan_credential_for_fingerprint(fingerprint);
    Ok(identity_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_name_validation_trims_and_rejects_controls() {
        assert_eq!(
            validate_identity_name("  Operators  ").unwrap(),
            "Operators"
        );
        assert!(validate_identity_name("").is_err());
        assert!(validate_identity_name("bad\nname").is_err());
        assert!(validate_identity_name(&"x".repeat(MAX_IDENTITY_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn identity_id_validation_is_canonical() {
        let identity_id = Uuid::new_v4();
        assert_eq!(
            validate_identity_id(&identity_id.to_string()).unwrap(),
            identity_id.to_string()
        );
        assert!(validate_identity_id("not-an-id").is_err());
    }
}
