use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use rand::distr::Alphanumeric;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};

#[derive(Serialize, Deserialize, Clone)]
struct PasswordEntry {
    service: String,
    username: String,
    password: String,
}

struct PasswordStore {
    passwords: Vec<PasswordEntry>,
    file: String,
}

impl PasswordStore {
    fn new(filepath: &str) -> Self {
        PasswordStore {
            passwords: Vec::new(),
            file: filepath.to_string(),
        }
    }

    fn add_password(&mut self, service: &str, username: &str, password: &str) {
        self.passwords.push(PasswordEntry {
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    fn list_passwords(&self) {
        for entry in self.passwords.iter() {
            println!(
                "service: {} | username: {}\n",
                entry.service, entry.username
            )
        }
    }

    fn get_password(&mut self, service: &str) -> Option<&PasswordEntry> {
        self.passwords.iter().find(|e| e.service == service)
    }

    fn save_to_file(&self, master_password: &str) -> io::Result<()> {
        let json = serde_json::to_string(&self.passwords)?;
        let encrypted = encrypt_data(json.as_bytes(), master_password);
        fs::write(&self.file, encrypted)?;
        Ok(())
    }

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

fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Erreur");
    input.trim().to_string()
}

fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    result.into()
}

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

fn generate_random_password(password_length: usize) -> String {
    let password: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(password_length)
        .map(char::from)
        .collect();
    password
}

fn main() {
    println!("Gestionnaire de mots de passe\n");

    let file_path = "passwords.enc";
    let master_password = get_input("Entrez le mot de passe maître : ");
    let mut store = match PasswordStore::load_from_file(file_path, &master_password) {
        Ok(store) => store,
        Err(_) => {
            println!(
                "Aucun fichier de mots de passe trouvé ou mot de passe incorrect. Création d'un nouveau magasin."
            );
            PasswordStore::new(file_path)
        }
    };

    loop {
        let choice = get_input(
            "============== Menu ==============\n1. Ajouter un mot de passe\n2. Afficher tous les mots de passe\n3. Mot de passe d'un service\n4. Sauvegarder et quitter\n 5. Quitter sans sauvegarder",
        );

        match choice.trim() {
            "1" => {
                let service = get_input("Entrez le nom du service : ");
                let username = get_input("Entrez le nom d'utilisateur : ");
                let password_choice =
                    get_input("Voulez-vous générer un mot de passe aléatoire ? (oui/non) : ");
                let password = if password_choice.to_lowercase() == "oui" {
                    let password_length = get_input("Entrez la taille de mot de passe voulue : ")
                        .trim()
                        .parse::<usize>()
                        .unwrap_or(12);
                    generate_random_password(password_length)
                } else {
                    get_input("Entrez le mot de passe : ")
                };
                store.add_password(&service, &username, &password);
                println!("Mot de passe ajouté avec succès !");
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
            "4" => match store.save_to_file(&master_password) {
                Ok(_) => {
                    println!("Mots de passe sauvegardés avec succès. Au revoir!");
                    break;
                }
                Err(e) => {
                    println!("Erreur lors de la sauvegarde : {}", e);
                }
            },
            "5" => {
                println!("Au revoir!");
                break;
            }
            _ => {
                println!("Choix invalide, veuillez réessayer.");
            }
        }
    }
}
