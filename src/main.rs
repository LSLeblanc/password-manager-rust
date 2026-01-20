use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};

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
        for entry in self.passwords.iter() {
            println!(
                "service: {} | username: {}\n",
                entry.service, entry.username
            )
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

/// Fonction pour obtenir une entrée utilisateur
fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Erreur");
    input.trim().to_string()
}

/// Lecture d'un mot de passe sans affichage (entrée cachée)
fn get_password_hidden(prompt: &str) -> String {
    prompt_password(prompt).expect("Erreur lors de la lecture du mot de passe")
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
    println!("Gestionnaire de mots de passe\n");

    // Chargement ou création du magasin de mots de passe
    let file_path = "passwords.enc";
    let master_password = get_password_hidden("Entrez le mot de passe maître : ");
    let mut store = match PasswordStore::load_from_file(file_path, &master_password) {
        // Si le fichier existe et le mot de passe est correct, charger le magasin
        Ok(store) => store,
        // Si le fichier n'existe pas ou le mot de passe est incorrect, créer un nouveau magasin
        Err(_) => {
            println!(
                "Aucun fichier de mots de passe trouvé ou mot de passe incorrect. Création d'un nouveau magasin."
            );
            PasswordStore::new(file_path)
        }
    };

    // Boucle principale du menu
    loop {
        let choice = get_input(
            "============== Menu ==============\n1. Ajouter un mot de passe\n2. Afficher tous les mots de passe\n3. Mot de passe d'un service\n4. Supprimer par service\n5. Sauvegarder et quitter\n6. Quitter sans sauvegarder",
        );

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
                println!("Mot de passe enregistré avec succès !");
            }
            "2" => {
                store.list_passwords();
            }
            "3" => {
                let service = get_input("Entrez le nom du service : ");
                match store.get_password(&service) {
                    Some(entry) => {
                        println!(
                            "Service: {}\nUsername: {}\nPassword: {}",
                            entry.service, entry.username, entry.password
                        );
                    }
                    None => {
                        println!("Aucun mot de passe trouvé pour ce service.");
                    }
                }
            }
            "4" => {
                let service = get_input("Entrez le nom du service à supprimer : ");
                let removed = store.delete_by_service(&service);
                if removed > 0 {
                    println!(
                        "{} entrées supprimées pour le service '{}'",
                        removed, service
                    );
                } else {
                    println!("Aucune entrée trouvée pour ce service.");
                }
            }
            "5" => match store.save_to_file(&master_password) {
                Ok(_) => {
                    println!("Mots de passe sauvegardés avec succès. Au revoir!");
                    break;
                }
                Err(e) => {
                    println!("Erreur lors de la sauvegarde : {}", e);
                }
            },
            "6" => {
                println!("Au revoir!");
                break;
            }
            _ => {
                println!("Choix invalide, veuillez réessayer.");
            }
        }
    }
}
