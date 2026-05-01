use crate::crypto::{self, CryptoError};
use crate::{Secret, Vault, VaultEntry};




//parcourt toutes les entrees de vault legacy et migration de v1 vers v2
impl From<LegacyVault> for Vault {
    // migration de v1 vers v2
    fn from(legacy: LegacyVault) -> Self {
        let entries = legacy
            .entries
            .into_iter()
            .map(|(k, entry)| {
                (
                    k, //Garde la meme cle pour l'entree
                    VaultEntry { //cree une nouvelle entree de vault a partir de l'entree legacy
                        key: entry.key,
                        secret: Secret {
                            value: entry.secret.value,
                        },
                        created_at: entry.created_at,
                        expires_at: entry.expires_at,
                        tags: entry.tags,
                        history: vec![],  //Nouveau : historique vide par defaut
                    },
                )
            })
            .collect();   //Regroupe tout dans une HashMap

// construit le nouveau Vault 

        Vault {
            entries,  // les entrees migrees
            version: legacy.version,
            created_at: legacy.created_at,
            last_modified: legacy.last_modified,
        }
    }
}
//test unitaire
#[cfg(test)]
mod tests {
    use super::{load_vault, save_vault, StorageError};
    use crate::crypto;
    use crate::{Secret, Vault, VaultEntry};
    use chrono::Utc;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use serde::Serialize;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
//function utilitaire
    fn temp_vault_path(test_name: &str) -> PathBuf {
        // Nom de fichier quasi unique pour eviter les collisions entre tests.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);

        std::env::temp_dir().join(format!("securevault-{test_name}-{nanos}.dat"))
    }

    fn sample_vault() -> Vault {
        // Petit jeu de donnees representatif pour tester la persistence.
        let now = Utc::now();
        let mut vault = Vault::new();
        vault.entries.insert(
            String::from("API_KEY"),
            VaultEntry {
                key: String::from("API_KEY"),
                secret: Secret {
                    value: String::from("secret-value"),
                },
                created_at: now,
                expires_at: None,
                tags: vec![String::from("prod"), String::from("api")],
                history: vec![],
            },
        );
        vault.last_modified = now;
        vault
    }

    #[test]
    fn save_then_load_roundtrip() {
        // Le vault sauvegarde doit etre relu a l'identique avec le bon mot de passe.
        let path = temp_vault_path("roundtrip");
        let vault = sample_vault();

        let save_result = save_vault(&vault, "master-password", &path);
        assert!(save_result.is_ok());

        let loaded = load_vault("master-password", &path);
        assert!(loaded.is_ok());
        let loaded = loaded.unwrap_or_else(|_| Vault::new());

        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(
            loaded.entries.get("API_KEY").map(|entry| entry.value()),
            Some("secret-value")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn wrong_password_is_reported() {
        // Une cle derivee depuis un mot de passe incorrect doit etre rejetee.
        let path = temp_vault_path("wrong-password");
        let vault = sample_vault();

        let save_result = save_vault(&vault, "correct-password", &path);
        assert!(save_result.is_ok());

        let loaded = load_vault("bad-password", &path);
        assert!(matches!(loaded, Err(StorageError::WrongPassword)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_format_is_reported() {
        // Un fichier trop court ou arbitraire doit etre signale comme format invalide.
        let path = temp_vault_path("invalid-format");
        let write_result = fs::write(&path, b"bad");
        assert!(write_result.is_ok());

        let loaded = load_vault("irrelevant", &path);
        assert!(matches!(loaded, Err(StorageError::InvalidFormat)));

        let _ = fs::remove_file(path);
    }

    #[derive(Debug, Serialize)]
    struct LegacySecretV1 {
        value: String,
    }

    #[derive(Debug, Serialize)]
    struct LegacyVaultEntryV1 {
        key: String,
        secret: LegacySecretV1,
        created_at: chrono::DateTime<Utc>,
        expires_at: Option<chrono::DateTime<Utc>>,
        tags: Vec<String>,
    }

    #[derive(Debug, Serialize)]
    struct LegacyVaultV1 {
        entries: std::collections::HashMap<String, LegacyVaultEntryV1>,
        version: u32,
        created_at: chrono::DateTime<Utc>,
        last_modified: chrono::DateTime<Utc>,
    }

    #[test]
    fn legacy_v1_vault_is_migrated_with_empty_history() {
        let path = temp_vault_path("legacy-migration");
        let now = Utc::now();

        let mut entries = std::collections::HashMap::new();
        entries.insert(
            String::from("API_KEY"),
            LegacyVaultEntryV1 {
                key: String::from("API_KEY"),
                secret: LegacySecretV1 {
                    value: String::from("legacy-secret"),
                },
                created_at: now,
                expires_at: None,
                tags: vec![String::from("prod")],
            },
        );

        let legacy = LegacyVaultV1 {
            entries,
            version: 1,
            created_at: now,
            last_modified: now,
        };

        let mut salt = [0_u8; 32];
        OsRng.fill_bytes(&mut salt);
        let key = crypto::derive_key("master-password", &salt).unwrap_or([0_u8; 32]);
        let serialized = bincode::serialize(&legacy).unwrap_or_default();
        let encrypted = crypto::encrypt(&serialized, &key).unwrap_or_default();

        let mut payload = Vec::with_capacity(4 + 32 + encrypted.len());
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&encrypted);
        let write_result = fs::write(&path, payload);
        assert!(write_result.is_ok());

        let loaded = load_vault("master-password", &path);
        assert!(loaded.is_ok());
        let loaded = loaded.unwrap_or_else(|_| Vault::new());
        let entry = loaded.entries.get("API_KEY");
        assert!(entry.is_some());
        assert_eq!(entry.map(|e| e.value()), Some("legacy-secret"));
        assert_eq!(entry.map(|e| e.history.len()), Some(0));

        let _ = fs::remove_file(path);
    }
}


