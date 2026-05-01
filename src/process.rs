use crate::Vault;
use std::io;
use std::process::{Command, ExitStatus};

/// Execute une commande enfant avec tous les secrets injectes comme variables d'environnement.
pub fn exec_with_vault(vault: &Vault, command: &str, args: &[String]) -> io::Result<ExitStatus> {
    // Premier essai: execution directe d'un binaire.
    let mut direct = Command::new(command);
    direct.args(args);
    match spawn_with_vault(vault, direct) {
        Ok(status) => Ok(status),
        // Fallback shell utile pour les commandes non executables directement
        // (ex: `env` absent sous Windows, builtins shell, alias).
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            spawn_with_vault(vault, shell_command(command, args))
        }
        Err(err) => Err(err),
    }
}

fn spawn_with_vault(vault: &Vault, mut child: Command) -> io::Result<ExitStatus> {
    // Chaque secret devient une variable `KEY=value` visible uniquement par l'enfant.
    for entry in vault.entries.values() {
        child.env(&entry.key, entry.value());
    }

    // L'appelant attend la terminaison et recupere le statut de sortie.
    child.status()
}

#[cfg(windows)]
fn shell_command(command: &str, args: &[String]) -> Command {
    let mut cmd = Command::new("cmd");
    if command.eq_ignore_ascii_case("env") && args.is_empty() {
        // `env` n'existe pas nativement sous Windows; `set` affiche l'environnement.
        cmd.arg("/C").arg("set");
    } else {
        cmd.arg("/C").arg(join_shell_command(command, args));
    }
    cmd
}

#[cfg(not(windows))]
fn shell_command(command: &str, args: &[String]) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(join_shell_command(command, args));
    cmd
}

fn join_shell_command(command: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_quote(command));
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    parts.join(" ")
}

#[cfg(windows)]
fn shell_quote(raw: &str) -> String {
    if raw.is_empty() {
        return "\"\"".to_owned();
    }
    if raw.contains([' ', '\t', '"']) {
        format!("\"{}\"", raw.replace('"', "\\\""))
    } else {
        raw.to_owned()
    }
}

#[cfg(not(windows))]
fn shell_quote(raw: &str) -> String {
    if raw.is_empty() {
        return "''".to_owned();
    }
    if raw
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '$' | '`' | '\\' | '!' | '&' | '|' | ';' | '<' | '>'))
    {
        format!("'{}'", raw.replace('\'', "'\"'\"'"))
    } else {
        raw.to_owned()
    }
}

/// Exporte les secrets en texte compatible avec un fichier `.env`.
pub fn export_env(vault: &Vault) -> String {
    let mut lines = Vec::with_capacity(vault.entries.len());

    for entry in vault.entries.values() {
        // Les caracteres sensibles sont echappes pour eviter de casser le format.
        let escaped = entry
            .value()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        lines.push(format!("{}=\"{}\"", entry.key, escaped));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::export_env;
    use crate::{Secret, Vault, VaultEntry};
    use chrono::Utc;

    #[test]
    fn export_env_quotes_and_escapes_values() {
        // On verifie que les guillemets et retours a la ligne sont correctement conserves.
        let now = Utc::now();
        let mut vault = Vault::new();
        vault.entries.insert(
            String::from("TOKEN"),
            VaultEntry {
                key: String::from("TOKEN"),
                secret: Secret {
                    value: String::from("line1\n\"quoted\""),
                },
                created_at: now,
                expires_at: None,
                tags: vec![],
                history: vec![],
            },
        );

        let env_output = export_env(&vault);

        assert!(env_output.contains("TOKEN=\"line1\\n\\\"quoted\\\"\""));
    }
}
