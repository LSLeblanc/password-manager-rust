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
