# ds_proxy

Proxy HTTP de chiffrement en streaming devant un object storage S3 et/ou
Swift. Le stockage ne voit que du chiffré ; le proxy chiffre à l'upload et
déchiffre au téléchargement, de façon transparente pour le client. Le readme
décrit l'installation et les modes ; ce fichier fixe ce qu'il faut savoir pour
travailler sur le code sans casser ses garanties.

## Carte du code

- `src/http/proxy.rs` : routes et middlewares. `/ping`, `/upstream/…`
  (relai chiffrant), `/local/encrypt/{name}` (chiffrement vers le disque).
- `src/http/handlers/` : `fetch` (GET, déchiffre), `forward` (PUT, chiffre),
  `simple_proxy` (toute autre méthode, relai sans transformation),
  `encrypt_to_file` / `fetch_file` (endpoints `/local`).
- `src/http/middlewares/mod.rs` : `verify_s3_signature` (auth des requêtes
  S3), `ensure_write_once` (verrou Redis sur les URL présignées d'écriture).
- `src/http/utils/` : `verify_signature` (vérification SigV4 entrante),
  `s3_helper` (re-signature sortante), `flavor` (détection S3 / Swift),
  `partial_extractor` (plages d'octets sur le flux déchiffré).
- `src/crypto/` : format de fichier (en-tête ds + secretstream
  xchacha20poly1305 par chunks), encodeur et décodeur en streaming.
- `src/config.rs` : lecture des flags et variables d'environnement,
  construction de l'URL amont, chemin des fichiers `/local`.
- `src/keyring*.rs` : keyring chiffré par un mot de passe maître, rotation.
- `src/write_once_service.rs` : verrou `SET NX EX` dans Redis.

## Déploiement de référence

- Mode **dual S3 + Swift**, `--write-once` actif avec Redis.
- L'application backend parle au proxy sur un réseau privé (socket Unix ou
  adresse interne). Elle seule utilise `/local`.
- Les navigateurs des usagers atteignent `/upstream` à travers un reverse
  proxy public (haproxy ou équivalent), avec des URL présignées S3 ou des
  TempURL Swift générées par l'application.
- Le bucket contient durablement des objets stockés en clair, que le proxy
  sert tels quels (repli « pas de préfixe ds = clair »). C'est voulu.

Exigence de déploiement qui en découle : le reverse proxy public ne doit
router que `/upstream` (et `/ping`). `/local` n'a pas d'authentification et
repose entièrement sur le fait de n'être joignable que depuis l'application.

## Modèle de menace

Acteurs de confiance : l'application backend, l'exploitant (variables
d'environnement, flags, keyring, mot de passe maître), le réseau privé entre
l'application et le proxy.

Le stockage amont est de confiance pour la disponibilité et l'intégrité, pas
pour la confidentialité : c'est la raison d'être du proxy. Quiconque lit le
bucket sans passer par le proxy ne doit rien apprendre du contenu.

Attaquants considérés :

1. Un usager qui détient une URL présignée ou une TempURL légitime, et qui
   essaie d'en tirer plus que l'opération pour laquelle elle a été émise
   (autre objet, autre méthode, rejeu, en-têtes ajoutés).
2. Un tiers qui a récupéré une telle URL après coup (historique, journaux,
   partage) pendant sa durée de validité.
3. Un lecteur des journaux du proxy ou de leur agrégateur.
4. Un acteur qui accède au bucket directement, sans le proxy.

Hors périmètre : un attaquant présent sur le réseau privé, le contrôle des
variables d'environnement ou de la ligne de commande, le déni de service.

## Invariants de sécurité

Chaque invariant indique où il est appliqué et le test qui le couvre. Une
modification qui en affaiblit un doit être discutée avant d'être écrite.

1. **Le stockage ne reçoit que du chiffré, le client ne reçoit que du
   déchiffré.** `forward` passe tout corps par `encode`, `fetch` par
   `decode`. Le contenu en clair n'existe qu'en mémoire du proxy. La
   longueur annoncée à l'amont est celle que l'encodeur produit :
   `encrypted_body` construit les deux ensemble.
   Tests : `tests/upload_and_download.rs`, `tests/encryption_tests.rs`.
2. **Une requête S3 sur `/upstream` n'est relayée que si sa signature SigV4
   est valide pour les credentials du proxy.** Une signature valide ne peut
   venir que de l'application, directement ou via une URL qu'elle a
   présignée. `verify_s3_signature`, `is_signature_valid`.
   Tests : `verify_signature.rs` (unitaires), `check_s3_signature`.
3. **Le proxy ne re-signe que ce que le client a signé.** Tout en-tête
   `x-amz-*` absent de `SignedHeaders` est refusé en 403, comme le fait S3
   (`x-amz-content-sha256` toléré). Sans cela, la re-signature avec les
   credentials du proxy donnerait du poids à un en-tête que personne n'a
   autorisé. `unsigned_amz_headers`, `sign_request` (préfixe `x-amz-`).
   Tests : `tests/unsigned_amz_headers.rs`, `verify_signature.rs`.
4. **L'hôte amont ne dépend jamais de la requête.** L'URL amont est une
   concaténation `base + chemin brut`, jamais un `Url::join`, pour qu'aucune
   forme de chemin ne puisse changer de schéma, d'hôte ou de port.
   Tests : `config.rs` (`test_ssrf_*`), `tests/traversal_attack.rs`.
5. **Une URL présignée d'écriture ne réussit qu'une fois par objet.** Le
   verrou Redis est calculé sur le chemin résolu (segments `.` et `..`,
   encodés ou non), le même que celui couvert par la signature, pour qu'une
   seule identité d'objet corresponde à un seul verrou. Une requête est
   reconnue présignée sur les clés de query décodées, et le verrou dure
   aussi longtemps que le credential reste acceptable, jamais moins d'une
   heure. Seule une réponse 2xx de l'amont consomme le verrou.
   `ensure_write_once`, `PresignedQuery`.
   Tests : `tests/ensure_write_once.rs`, `presigned.rs` (unitaires).
6. **`/local` ne sort jamais de son répertoire.** Le nom demandé est réduit
   à son dernier segment ; `..`, `/` et vide sont refusés.
   `local_encryption_path_for`. Test : `config.rs`.
7. **Les journaux aux niveaux `info`, `warn` et `error` ne contiennent ni
   en-têtes de requête ni jetons.** `X-Auth-Token` et `X-Amz-Security-Token`
   ne doivent jamais y apparaître. On journalise méthode, chemin, statut.
   Les niveaux `debug` et `trace` ne sont pas destinés à la production.
8. **Le mot de passe maître et les clés ne sont lus qu'au démarrage**, depuis
   `DS_PASSWORD`, `--password-file` ou le keyring, et ne sont jamais
   journalisés ni renvoyés dans une réponse.
9. **En mode Swift, le proxy n'élargit aucun droit.** Il relaie la requête
   telle quelle, sans credentials propres ; l'authentification appartient à
   l'amont.

## Limites connues et décisions ouvertes

Ces points sont connus et assumés en l'état. Les rouvrir demande une décision
produit, pas seulement un correctif.

- Le format de fichier ne marque pas la fin du flux (`TAG_FINAL` absent) :
  le décodeur ne peut pas distinguer un objet complet d'un objet coupé sur
  une frontière de chunk. Corriger impose une évolution de format.
- `simple_proxy` relaie toute méthode autre que GET et PUT sans
  transformation. Une liste blanche de méthodes est envisageable.
- Une URL présignée reste acceptée 15 minutes après son expiration, et
  aucune durée maximale n'est imposée à `x-amz-expires`.
- Le parseur de signature suppose des en-têtes bien formés (`expect` sur
  `x-amz-date`, `SignedHeaders`). Une valeur malformée provoque un panic au
  lieu d'une 400.
- Les endpoints `/local` n'ont pas d'authentification propre (voir
  l'exigence de déploiement ci-dessus).

## Conventions

- Commits atomiques, titre conventionnel `type(scope): …` en anglais ;
  `breaking(scope):` pour un changement cassant. Pas de trailer
  d'attribution.
- Titres et descriptions de PR en anglais. Le readme et ce fichier sont en
  français.
- Le dépôt est public : une PR, un commit ou une issue décrit le correctif
  et la garantie apportée, jamais la marche à suivre pour exploiter le
  défaut.
- Un correctif de sécurité arrive avec le test qui échoue sans lui.
- Écrire le code le plus simple qui passe les tests. Une abstraction, un
  garde, une tâche de fond ou un cas limite ne se justifie que par un
  comportement démontré, en lisant les sources du framework ou par un test
  qui reproduit le cas réel, jamais par un cas supposé. Une piste issue d'un
  rapport ou d'une revue se vérifie avant d'être codée. Une optimisation qui
  coûte en lisibilité, comme éviter une allocation sur un chemin rare, se
  justifie par une mesure, sinon on prend la forme lisible.

## Vérifications

```
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test --all-features
```

Les tests d'intégration lancent un vrai binaire `ds_proxy`, un backend node
(`npm install` dans `tests/fixtures/server-static`), `redis-server` et
`curl`. Ils sont sérialisés (`#[serial(servers)]`) et occupent les ports
4444, 3333, 5555 ainsi que la socket `/tmp/actix-uds.socket`. Chaque test
attend environ 4 secondes le démarrage des serveurs.
