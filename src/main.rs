mod audit;
mod cli;
mod crypto;
mod process;
mod storage;

// `chrono` sert a horodater les secrets et le vault.
use chrono::{DateTime, Utc};
// `serde` permet de serialiser/deserialiser les structures du vault pour `bincode`.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Represente un secret individuel stocke dans le vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    // Valeur sensible du secret, decryptee uniquement en memoire.
    pub value: String,
}

// Snapshot d'une ancienne valeur, conservee pour l'historique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    // Ancienne valeur du secret.
    pub value: String,
    // Date de remplacement de cette valeur.
    pub replaced_at: DateTime<Utc>,
}

/// Represente une entree individuelle stockee dans le vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    // Nom logique du secret, reutilise aussi comme cle de recherche.
    pub key: String,
    // Contenu sensible associe a cette entree.
    pub secret: Secret,
    // Date de creation du secret.
    pub created_at: DateTime<Utc>,
    // Date d'expiration optionnelle.
    pub expires_at: Option<DateTime<Utc>>,
    // Etiquettes libres pour filtrage et organisation.
    pub tags: Vec<String>,
    // Historique des anciennes valeurs (plus ancien -> plus recent).
    #[serde(default)]
    pub history: Vec<SecretVersion>,
}

/// Represente l'ensemble du contenu logique du vault avant chiffrement sur disque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    // Index principal des secrets par nom.
    pub entries: HashMap<String, VaultEntry>,
    // Version logique de la structure du vault.
    pub version: u32,
    // Date de creation initiale du vault.
    pub created_at: DateTime<Utc>,
    // Date de derniere modification du vault.
    pub last_modified: DateTime<Utc>,
}

impl Vault {
    /// Cree un vault vide avec ses metadonnees initialisees.
    pub fn new() -> Self {
        // Une meme date de reference est utilisee pour garder des metadonnees coherentes.
        let now = Utc::now();

        Self {
            entries: HashMap::new(),
            version: 1,
            created_at: now,
            last_modified: now,
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultEntry {
    /// Indique si le secret est expire au moment de l'appel.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|expires_at| expires_at <= Utc::now())
            .unwrap_or(false)
    }

    /// Retourne la valeur en clair du secret.
    pub fn value(&self) -> &str {
        &self.secret.value
    }
}

fn main() {
    // Toute l'orchestration passe par la CLI.
    // En cas d'erreur, on affiche un message clair puis on quitte avec un code non nul.
    if let Err(err) = cli::run() {
        eprintln!("Erreur : {err}");
        std::process::exit(1);
    }
}
