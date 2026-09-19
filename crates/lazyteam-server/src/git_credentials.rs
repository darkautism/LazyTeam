use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use rand::RngCore;
use std::{io::Write, path::Path};

const VERSION: &str = "v1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub(crate) fn parse_master_key(raw: &str) -> anyhow::Result<[u8; KEY_LEN]> {
    let raw = raw.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| STANDARD.decode(raw))
        .map_err(|_| anyhow::anyhow!("LAZYTEAM_GIT_CREDENTIAL_KEY must be base64-encoded 32 bytes"))?;
    let key: [u8; KEY_LEN] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("LAZYTEAM_GIT_CREDENTIAL_KEY must decode to exactly 32 bytes"))?;
    Ok(key)
}

pub(crate) fn load_or_create_master_key(path: &Path, configured: Option<&str>) -> anyhow::Result<[u8; KEY_LEN]> {
    if let Some(raw) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return parse_master_key(raw);
    }
    match std::fs::read_to_string(path) {
        Ok(raw) => return parse_master_key(&raw),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).map_err(Into::into),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut key = [0u8; KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    let encoded = URL_SAFE_NO_PAD.encode(key);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            parse_master_key(&std::fs::read_to_string(path)?)
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn encrypt(key: &[u8; KEY_LEN], plaintext: &str) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid Git credential encryption key"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("encrypt Git credential"))?;
    Ok(format!(
        "{VERSION}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce_bytes),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

pub(crate) fn decrypt(key: &[u8; KEY_LEN], encoded: &str) -> anyhow::Result<String> {
    let mut parts = encoded.split('.');
    if parts.next() != Some(VERSION) {
        anyhow::bail!("unsupported Git credential ciphertext version");
    }
    let nonce = parts.next().ok_or_else(|| anyhow::anyhow!("Git credential nonce missing"))?;
    let ciphertext = parts.next().ok_or_else(|| anyhow::anyhow!("Git credential ciphertext missing"))?;
    if parts.next().is_some() {
        anyhow::bail!("invalid Git credential ciphertext");
    }
    let nonce = URL_SAFE_NO_PAD.decode(nonce).map_err(|_| anyhow::anyhow!("decode Git credential nonce"))?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| anyhow::anyhow!("invalid Git credential nonce"))?;
    let ciphertext = URL_SAFE_NO_PAD.decode(ciphertext).map_err(|_| anyhow::anyhow!("decode Git credential ciphertext"))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid Git credential encryption key"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("decrypt Git credential"))?;
    String::from_utf8(plaintext).map_err(|_| anyhow::anyhow!("Git credential is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_credentials_round_trip_and_wrong_key_fails() {
        let key = [7u8; KEY_LEN];
        let other = [8u8; KEY_LEN];
        let value = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n";
        let encoded = encrypt(&key, value).unwrap();
        assert!(!encoded.contains("secret"));
        assert_eq!(decrypt(&key, &encoded).unwrap(), value);
        assert!(decrypt(&other, &encoded).is_err());
    }

    #[test]
    fn master_key_requires_exactly_32_bytes() {
        let encoded = URL_SAFE_NO_PAD.encode([1u8; KEY_LEN]);
        assert_eq!(parse_master_key(&encoded).unwrap(), [1u8; KEY_LEN]);
        assert!(parse_master_key(&URL_SAFE_NO_PAD.encode([1u8; 31])).is_err());
    }

    #[test]
    fn master_key_is_created_once_and_reused() {
        let root = std::env::temp_dir().join(format!("lazyteam-key-{}", uuid::Uuid::new_v4()));
        let path = root.join("git-credential.key");
        let first = load_or_create_master_key(&path, None).unwrap();
        let second = load_or_create_master_key(&path, None).unwrap();
        assert_eq!(first, second);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
