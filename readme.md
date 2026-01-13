# DS Proxy

## Contexte

DS Proxy est un proxy HTTP de chiffrement en streaming compatible S3 et Swift. Il est utilisé sur [demarche.numerique.gouv.fr](https://github.com/demarche-numerique/demarche.numerique.gouv.fr).
Il permet de se prémunir d'accès non autorisé aux espaces de stockages mutualisés de type object storage en y stockant uniquement de la donnée chiffrée.

Fonctionnalités :
- chiffre et déchiffre de manière transparente pour le client des fichiers en http en les stockants sur l'object storage
- chiffre et stocke en local de gros fichier (`/local/`) depuis un envoi http
- chiffre et déchiffre des fichiers sur le système de fichier
- est performant
- supporte de multiples clés de chiffrement pour se conformer à une politique de péremption de clés
- possède une url de health check `/ping` qui renvoie une 404 si le fichier `maintenance` est présent à côté du binaire
- peut garantir qu'un fichier est uploadé une fois

## Limitations S3 connues

Pour le moment, le proxy supporte l'upload des fichiers en mode S3 uniquement via la méthode PUT.

N'est pas supporté pour le moment :
- l'upload multipart
- le chunk upload

Également, de part son implémentation actuelle, le téléchargement parallèle de fichier a une performance médiocre.

## Pour commencer

prérequis: 
- [rust](rust-lang.org) dans la version précisée par le fichier `Cargo.toml`
- et dans le cadre de la démo [node](https://nodejs.org)

puis lancer le script `launch_demo.sh` qui compilera le proxy, le démarrera, et qui lancera un faux backend object storage en node.

## Installation

- compiler le proxy pour la production: `cargo build --release`, le binaire se trouve à présent ici : `target/release/ds_proxy`
- placer le binaire sur votre server et utiliser votre système habituel pour le superviser

Exemple d'un fichier service minimal de supervision par systemd:

```
[Unit]
Description=DS Proxy Service
After=network.target

[Service]
ExectStart=/usr/bin/ds_proxy proxy --password-file /var/ds_proxy/password --salt a_32_charactere_long_salt_123456 --keyring-file /var/ds_proxy/keyring.toml  --local-encryption-directory /var/ds_proxy/local_encryption/ --address 0.0.0.0:4444 --upstream_url 'https://my-storage-object.com'

Environment=RUST_LOG="actix_web=info"
...
```

### Garder le mot de passe en mémoire

Pour éviter que le mot de passe ne reste sur le disque et en suivant https://www.netmeister.org/blog/passing-passwords.html, nous utilisons `mkfifo` pour créer un named pipe qui nous permet de le transmettre en restant en mémoire.
En voici le principe :
```
mkfifo -m 0600 password_file
systemctl start ds_proxy
systemd-ask-password > password_file
rm -f password_file
```

## Dans le détail

### Algo
DS Proxy utilise actuellement l'algorithme de chiffrement [xchacha20poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) proposé par la librairie [sodium](https://doc.libsodium.org/) dont l'interface est portée en rust par [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide).

Les clés de chiffrement sont stockées sur un fichier `keyring.toml`. Ce fichier est lui-même chiffré à l'aide d'un mot de passe maître et d'un sel.

## Option

### Write Once

Vous pouvez garantir que le proxy acceptera de transférer à l'object storage un fichier une seule fois. Cette option permet d'éviter des problèmes de sécurité liés à l'exposition des URLs temporaires des stockages, qui peuvent être utilisées plusieurs fois si elles ne sont pas correctement protégées.

Pour activer cette fonctionnalité, vous devez disposer d'une instance Redis accessible et fournir son URL via l'option suivante :
```bash
--write-once --redis_url=redis://127.0.0.1
```

**Important**

La librairie utilisée pour gérer le pool Redis est `deadpool-redis`. Par défaut, cette librairie [n'applique pas de timeout](https://docs.rs/deadpool-redis/latest/deadpool_redis/struct.PoolConfig.html#fields), ce qui peut poser problème si Redis devient indisponible. Pour éviter de bloquer le système, vous pouvez configurer les options de timeout suivantes :

- **wait** : Temps d'attente pour obtenir une connexion dans le pool. Par défaut à 200ms. Personnalisable en ms via l'argument `--redis_timeout_wait` ou la variable d'environnement `REDIS_TIMEOUT_WAIT`.
- **create** : Temps maximum pour créer une nouvelle connexion. Par défaut à 200ms. Personnalisable en ms via l'argument `--redis_timeout_create` ou la variable d'environnement `REDIS_TIMEOUT_CREATE`.
- **recycle** : Temps maximum pour recycler une connexion existante. Par défaut à 200ms. Personnalisable en ms via l'argument `--redis_timeout_recycle` ou la variable d'environnement `REDIS_TIMEOUT_RECYCLE`.

Exemple :
```bash
--redis_timeout_wait=10 --redis_timeout_create=5 --redis_timeout_recycle=2
```

Le **pool size** (taille du pool de connexions Redis) est fixé par défaut à 16. Vous pouvez le personnaliser via l'argument `--redis_pool_max_size` ou la variable d'environnement `REDIS_POOL_MAX_SIZE`.

Exemple :
```bash
--redis_pool_max_size=32
```

## Comment contribuer ?

**ds_proxy** est un [logiciel libre](https://fr.wikipedia.org/wiki/Logiciel_libre) sous [licence AGPL](LICENSE.txt).

Vous souhaitez y apporter des changements ou des améliorations ? Lisez notre [guide de contribution](CONTRIBUTING.md).
