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

    fn add_password(&mut self, url: &str, username: &str, password: &str) {
        self.passwords.push(PasswordEntry {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    fn list_passwords(&mut self) {
        for entry in self.passwords.iter() {
            println!(
                "url : {} | username : {} | password : {}\n",
                entry.url, entry.username, entry.password
            )
        }
    }

    // fn save_to_file() {}

    // fn load_from_file() {}
}

struct PasswordEntry {
    url: String,
    username: String,
    password: String,
}

fn main() {
    println!("Gestionnaire de mots de passe\n");
    loop {
        println!(
            "====== Menu ======\n1. Ajouter un mot de passe\n2. Afficher les mots de passe\n3. Quitter"
        );

        let mut choice = String::new();
        std::io::stdin()
            .read_line(&mut choice)
            .expect("Échec de la lecture de l'entrée");

        match choice.trim() {
            "1" => {
                println!("Fonctionnalité d'ajout de mot de passe (à implémenter)");
            }
            "2" => {
                println!("Fonctionnalité d'affichage des mots de passe (à implémenter)");
            }
            "3" => {
                println!("Au revoir!");
                break;
            }
            _ => {
                println!("Choix invalide, veuillez réessayer.");
            }
        }
    }
}
