Ce projet a été fait en Rust. Pour le lançer, un simple ```cargo install``` et ```cargo run``` devrait suffire.

## A noter qu'il est nécessaire d'avoir une installation de openssl sur sa machine.

De manière générale, si vous avez un doute sur les différentes commandes du CLI, écrivez :
```sh
cargo run -- <votre-commande> -h
```

# Question 1

J'ai fourni dans l'archive une image de test autre que le diplôme
Voici les différentes commades à éxécuter pour pouvoir tester la stéganographie LSB :

```sh
cargo run -- test steg-write images/sources/orangutan.png images/targets/test_steg.png "ifrit le boss"

cargo run -- test steg-read images/sources/test_steg.png
```

Vous pouvez bien évidemment essayer un autre message.

# Question 2
Je n'ai pas inclus les clés car il est très simple avec cette outil de les générer.

Voici les différentes commandes à éxécuter :

```sh
# Par défaut les clés générées seront de 256 octets, mais vous pouvez le changer en paramètre
cargo run -- test generate-rsa-keys

cargo run -- test sign-message "zobi la mouche" -f .private_key.pem

# Notez la signature qui vous a été généré
cargo run -- test verify-message "zobi la mouche" <votre_signature> -f public_key.pem

# Le cli affiche true si la signature est vérifié sinon false (on est minimaliste ici)
```

# Question 3

```sh
cargo run -- test write-text-image images/sources/orangutan.png images/targets/test_write.png orangoutan
```

# Question 4

Pour pouvoir créer un diplome voici la commande à éxécuter :

```sh
cargo run -- create-degree <nom_etudiant> <note> -f <chemin_vers_cle_privee>

# Par exemple
cargo run -- create-degree "Voldimou Fernandia" 3 -f ./.private_key.pem
```

Le fichier se trouvera à l'emplacemebnt ```./images/targets/Voldimou_Fernandia.png```

# Question 5

Pour pouvoir ensuite le vérifier :

```sh
cargo run -- read-degree <chemin_vers-image> -f <chemin_vers_cle_publique>

# Ou, pour continuer notre exemple :
cargo run -- read-degree ./images/targets/Voldimou_Fernandia.png -f public_key.pem
```

La sortie devrait être similaire à :

```
Voldimou_Fernandia | 03 
The degree is certified to be from NIHCAMCURT !
```

On peut donc voir que le diplôme est certifié de venir en provenance de NIHCAMCURT, que cela concerne bien l'étudiant Voldimou Fernandia et qu'il a eu 03/20 (très fort)!