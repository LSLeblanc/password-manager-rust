use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use arboard::Clipboard;
use colored::Colorize;
use once_cell::sync::Lazy;
use rand::Rng;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone)]
/// Structure représentant une entrée de mot de passe pour un service donné
struct PasswordEntry {
    /// Nom du service (e.g., "gmail")
    service: String,
    /// Nom d'utilisateur associé au service
    username: String,
    /// Mot de passe associé au service
    password: String,
}

/// Structure principale pour gérer les mots de passe
struct PasswordStore {
    /// Liste des entrées de mots de passe
    passwords: Vec<PasswordEntry>,
    /// Chemin du fichier de stockage
    file: String,
}

impl PasswordStore {
    /// Crée un nouveau magasin de mots de passe
    fn new(filepath: &str) -> Self {
        PasswordStore {
            passwords: Vec::new(),
            file: filepath.to_string(),
        }
    }

    /// Supprime toutes les entrées correspondant à un service donné.
    /// Retourne le nombre d'entrées supprimées.
    fn delete_by_service(&mut self, service: &str) -> usize {
        let before = self.passwords.len();
        self.passwords.retain(|e| e.service != service);
        before - self.passwords.len()
    }

    /// Ajoute une nouvelle entrée de mot de passe
    fn add_password(&mut self, service: &str, username: &str, password: &str) {
        self.passwords.push(PasswordEntry {
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Liste tous les services et noms d'utilisateur stockés
    fn list_passwords(&self) {
        if self.passwords.is_empty() {
            print_info("Aucune entrée enregistrée.");
            return;
        }

        // Calcul des largeurs de colonnes
        let service_w = self
            .passwords
            .iter()
            .map(|e| e.service.len())
            .max()
            .unwrap_or(7)
            .max("Service".len());
        let user_w = self
            .passwords
            .iter()
            .map(|e| e.username.len())
            .max()
            .unwrap_or(9)
            .max("Utilisateur".len());

        // En-tête
        println!(
            "{}  {:service_w$}  {:user_w$}",
            "#".bright_cyan().bold(),
            "Service".bold(),
            "Utilisateur".bold(),
            service_w = service_w,
            user_w = user_w
        );
        println!("{}", "-".repeat(service_w + user_w + 5).bright_black());

        // Lignes
        for (i, e) in self.passwords.iter().enumerate() {
            println!(
                "{}  {:service_w$}  {:user_w$}",
                format!("{:>2}:", i + 1).bright_black(),
                e.service,
                e.username,
                service_w = service_w,
                user_w = user_w
            );
        }
    }

    /// Récupère une entrée de mot de passe pour un service donné
    fn get_password(&mut self, service: &str) -> Option<&PasswordEntry> {
        self.passwords.iter().find(|e| e.service == service)
    }

    /// Sauvegarde les mots de passe chiffrés dans un fichier
    fn save_to_file(&self, master_password: &str) -> io::Result<()> {
        let json = serde_json::to_string(&self.passwords)?;
        let encrypted = encrypt_data(json.as_bytes(), master_password);
        fs::write(&self.file, encrypted)?;
        Ok(())
    }

    /// Charge les mots de passe chiffrés depuis un fichier
    fn load_from_file(file_path: &str, master_password: &str) -> io::Result<Self> {
        let encrypted_data = fs::read(file_path)?;
        let decrypted = decrypt_data(&encrypted_data, master_password)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let json = String::from_utf8(decrypted)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let passwords: Vec<PasswordEntry> = serde_json::from_str(&json)?;
        Ok(PasswordStore {
            passwords,
            file: file_path.to_string(),
        })
    }
}

/// Fonction pour obtenir une entrée utilisateur (affiche le prompt stylé)
fn get_input(prompt: &str) -> String {
    println!("{} {}", "?".bright_cyan().bold(), prompt.bold());
    print!("{} ", "›".bright_cyan());
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Erreur");
    input.trim().to_string()
}

/// Lecture d'un mot de passe sans affichage (entrée cachée)
fn get_password_hidden(prompt: &str) -> String {
    println!("{} {}", "?".bright_cyan().bold(), prompt.bold());
    prompt_password("› ").expect("Erreur lors de la lecture du mot de passe")
}

fn print_title(title: &str) {
    let bar = "═".repeat(title.len() + 2);
    println!("\n{}", format!("╔{}╗", bar).bright_cyan());
    println!("{}", format!("║ {} {}", title.bold(), "║").bright_cyan());
    println!("{}\n", format!("╚{}╝", bar).bright_cyan());
}

fn print_section(title: &str) {
    println!("\n{} {}", "›".bright_cyan(), title.bold());
}

fn print_success(msg: &str) {
    println!("{} {}", "✔".green().bold(), msg);
}

fn print_error(msg: &str) {
    println!("{} {}", "✖".red().bold(), msg.red());
}

fn print_info(msg: &str) {
    println!("{} {}", "ℹ".bright_blue().bold(), msg);
}

static CLIPBOARD: Lazy<Mutex<Clipboard>> = Lazy::new(|| {
    // Create once and keep alive for the whole program lifetime
    Mutex::new(Clipboard::new().expect("Impossible d'initialiser le presse-papiers"))
});

/// Copie un texte dans le presse-papiers du système
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut guard = CLIPBOARD
        .lock()
        .map_err(|_| "Erreur interne: mutex presse-papiers".to_string())?;
    guard
        .set_text(text.to_string())
        .map_err(|e| format!("Erreur presse-papiers: {}", e))?;
    Ok(())
}

fn print_menu() {
    print_title("Gestionnaire de mots de passe");
    println!(
        "{}   {} Ajouter un mot de passe\n",
        "1".bold(),
        "•".bright_cyan()
    );
    println!(
        "{}   {} Afficher tous les mots de passe\n",
        "2".bold(),
        "•".bright_cyan()
    );
    println!(
        "{}   {} Mot de passe d'un service\n",
        "3".bold(),
        "•".bright_cyan()
    );
    println!(
        "{}   {} Supprimer par service\n",
        "4".bold(),
        "•".bright_cyan()
    );
    println!(
        "{}   {} Sauvegarder et quitter\n",
        "5".bold(),
        "•".bright_cyan()
    );
    println!(
        "{}   {} Quitter sans sauvegarder\n",
        "6".bold(),
        "•".bright_cyan()
    );
}

// Dossier où sont stockés les coffres (.enc)
const VAULT_DIR: &str = "vaults";

fn ensure_vault_dir() -> io::Result<()> {
    fs::create_dir_all(VAULT_DIR)
}

fn vault_path_for_user(username: &str) -> String {
    // Sanitize simple: conserver alphanumérique, '_' et '-'
    let sanitized: String = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let name = if sanitized.is_empty() {
        "default"
    } else {
        sanitized.as_str()
    };
    format!("{}/{}.enc", VAULT_DIR, name)
}

/// Dérive une clé de chiffrement à partir du mot de passe maître
fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    result.into()
}

/// Chiffre les données avec AES-256-GCM
fn encrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data).expect("encryption failure");

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    result
}

/// Déchiffre les données avec AES-256-GCM
fn decrypt_data(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 12 {
        return Err("Invalid encrypted data".to_string());
    }

    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&encrypted_data[0..12]);
    let ciphertext = &encrypted_data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed - wrong password?".to_string())
}

/// Génère un mot de passe aléatoire avec contraintes (min 1 minuscule, 1 majuscule, 1 chiffre, 1 symbole si demandé)
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/|~";
const CHARSET_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const CHARSET_ALNUM_SYM: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?/|~";

fn generate_random_password(password_length: usize, with_symbols: bool) -> String {
    let mut rng = rand::rng();
    let min_required = if with_symbols { 4 } else { 3 };
    let target_len = password_length.max(min_required);

    let mut pwd: Vec<u8> = Vec::with_capacity(target_len);

    // Ajouter au moins un caractère de chaque catégorie requise
    pwd.push(LOWER[rng.random_range(0..LOWER.len())]);
    pwd.push(UPPER[rng.random_range(0..UPPER.len())]);
    pwd.push(DIGITS[rng.random_range(0..DIGITS.len())]);
    if with_symbols {
        pwd.push(SYMBOLS[rng.random_range(0..SYMBOLS.len())]);
    }

    // Compléter avec l'ensemble autorisé
    let allowed = if with_symbols {
        CHARSET_ALNUM_SYM
    } else {
        CHARSET_ALNUM
    };
    while pwd.len() < target_len {
        pwd.push(allowed[rng.random_range(0..allowed.len())]);
    }

    // Mélanger (Fisher-Yates)
    for i in (1..pwd.len()).rev() {
        let j = rng.random_range(0..=i);
        pwd.swap(i, j);
    }

    String::from_utf8(pwd).expect("charset should be valid ASCII")
}

fn main() {
    print_title("Gestionnaire de mots de passe");

    // Sélection du coffre par utilisateur et création du dossier si besoin
    if let Err(e) = ensure_vault_dir() {
        print_error(&format!(
            "Impossible de préparer le dossier des coffres: {}",
            e
        ));
        return;
    }

    let username = get_input("Entrez votre identifiant utilisateur : ");
    let file_path = vault_path_for_user(&username);

    // Chargement ou création du magasin de mots de passe
    let master_password = get_password_hidden("Entrez le mot de passe maître : ");
    let mut store = match PasswordStore::load_from_file(&file_path, &master_password) {
        // Si le fichier existe et le mot de passe est correct, charger le magasin
        Ok(store) => store,
        // Si le fichier n'existe pas ou le mot de passe est incorrect, créer un nouveau magasin
        Err(_) => {
            if Path::new(&file_path).exists() {
                print_error("Mot de passe incorrect. Impossible d'ouvrir le coffre existant.");
                print_info("Vous pouvez réessayer en relançant l'application.");
                return;
            } else {
                print_info(&format!(
                    "Aucun coffre trouvé pour l'utilisateur '{}'. Création d'un nouveau coffre.",
                    username
                ));
                PasswordStore::new(&file_path)
            }
        }
    };

    // Boucle principale du menu
    loop {
        print_menu();
        let choice = get_input("Votre choix (1-6)");

        match choice.trim() {
            "1" => {
                let service = get_input("Entrez le nom du service : ");

                // Vérifier l'existence et proposer le remplacement
                let exists = store.passwords.iter().any(|e| e.service == service);
                if exists {
                    let confirm = get_input(
                        "Ce service possède déjà un mot de passe. Le remplacer ? (oui/non) : ",
                    )
                    .to_lowercase();
                    if confirm != "oui" && confirm != "o" {
                        println!("Opération annulée.");
                        continue; // revenir au menu principal sans quitter
                    }
                    // Supprimer toutes les entrées existantes pour garantir l'unicité
                    store.delete_by_service(&service);
                }

                let username = get_input("Entrez le nom d'utilisateur : ");
                let password_choice =
                    get_input("Voulez-vous générer un mot de passe aléatoire ? (oui/non) : ");
                let password = if password_choice.to_lowercase() == "oui" {
                    let password_length = get_input("Entrez la taille de mot de passe voulue : ")
                        .trim()
                        .parse::<usize>()
                        .unwrap_or(12);
                    let include_symbols = get_input("Inclure des symboles ? (oui/non) : ")
                        .to_lowercase()
                        .trim()
                        .to_string();
                    let with_symbols = include_symbols == "oui" || include_symbols == "o";
                    generate_random_password(password_length, with_symbols)
                } else {
                    get_password_hidden("Entrez le mot de passe : ")
                };
                store.add_password(&service, &username, &password);
                print_success("Mot de passe enregistré avec succès !");
            }
            "2" => {
                print_section("Entrées enregistrées");
                store.list_passwords();

                // Si des entrées existent, proposer la copie dans le presse-papiers
                if !store.passwords.is_empty() {
                    let selection = get_input(
                        "Entrez le numéro du mot de passe à copier (Entrée pour revenir) : ",
                    );
                    let sel = selection.trim();
                    if !sel.is_empty() {
                        match sel.parse::<usize>() {
                            Ok(n) if n >= 1 && n <= store.passwords.len() => {
                                let pwd = &store.passwords[n - 1].password;
                                match copy_to_clipboard(pwd) {
                                    Ok(_) => {
                                        print_success("Mot de passe copié dans le presse-papiers.")
                                    }
                                    Err(e) => print_error(&format!(
                                        "Impossible de copier dans le presse-papiers: {}",
                                        e
                                    )),
                                }
                            }
                            _ => print_error("Sélection invalide."),
                        }
                    }
                }
            }
            "3" => {
                let service = get_input("Entrez le nom du service : ");
                match store.get_password(&service) {
                    Some(entry) => {
                        print_section("Détails du service");
                        println!("{} {}", "Service:".bold(), entry.service);
                        println!("{} {}", "Utilisateur:".bold(), entry.username);
                        println!("{} {}", "Mot de passe:".bold(), entry.password);

                        // Proposer la copie dans le presse-papiers
                        let copy_choice = get_input(
                            "Copier le mot de passe dans le presse-papiers ? (oui/non) : ",
                        )
                        .to_lowercase();
                        if copy_choice == "oui" || copy_choice == "o" {
                            match copy_to_clipboard(&entry.password) {
                                Ok(_) => {
                                    print_success("Mot de passe copié dans le presse-papiers.")
                                }
                                Err(e) => print_error(&format!(
                                    "Impossible de copier dans le presse-papiers: {}",
                                    e
                                )),
                            }
                        }
                    }
                    None => {
                        print_error("Aucun mot de passe trouvé pour ce service.");
                    }
                }
            }
            "4" => {
                let service = get_input("Entrez le nom du service à supprimer : ");
                let removed = store.delete_by_service(&service);
                if removed > 0 {
                    print_success(&format!(
                        "{} entrées supprimées pour le service '{}'",
                        removed, service
                    ));
                } else {
                    print_error("Aucune entrée trouvée pour ce service.");
                }
            }
            "5" => match store.save_to_file(&master_password) {
                Ok(_) => {
                    print_success("Mots de passe sauvegardés avec succès. Au revoir!");
                    break;
                }
                Err(e) => {
                    print_error(&format!("Erreur lors de la sauvegarde : {}", e));
                }
            },
            "6" => {
                print_info("Au revoir!");
                break;
            }
            _ => {
                print_error("Choix invalide, veuillez réessayer.");
            }
        }
    }
}
