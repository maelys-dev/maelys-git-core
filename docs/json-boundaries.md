# Frontières JSON : une seule bibliothèque, maelys-json

Décision d'architecture du **2026-10-18** (cycle GIT-C05), qui révoque la
coexistence durable décidée le 2026-09-05 (voir [Historique](#historique)).
Bibliothèque : maelys-json, tag **`v0.3.1`**, commit
`3cfef055ba900816f0ba71c98380cd8dd2c9f94c`, épinglé dans
[`cmake/dependencies.cmake`](../cmake/dependencies.cmake).

## Décision

maelys-json lit toutes les entrées JSON externes avec des limites explicites
et écrit toutes les données JSON du produit et de ses tests : données des
commandes CLI, lignes du protocole de l'agent, forme de déduplication du
journal, configuration générée et reçus. Le framework maelys-cli écrit ses
propres enveloppes, autour des données qu'il reçoit telles quelles par
`maelys_cli_succeed_trusted`. Jansson n'est plus une dépendance : ni la
construction, ni la CI, ni l'image Linux ne le demandent, et aucun programme
ni aucune bibliothèque statique du produit ne porte un de ses symboles. Un
test de garde (`maelys-git-json-single-library`) le vérifie sur l'arbre et
sur les binaires.

Les octets écrits restent ceux de la version précédente, à trois
différences près :

- **Casse des échappements `\u`** : minuscule (`\u001f`) au lieu de
  majuscule (`\u001F`), dans un vrai échappement d'une chaîne ou d'une clé.
- **Ordre des clés** : unités UTF-16 (RFC 8785) au lieu des octets UTF-8.
  Les clés écrites par le produit sont ASCII ; la différence n'apparaît que
  dans les payloads recopiés, donc dans la forme de déduplication.
- **Deux lignes jusqu'ici dans l'ordre d'insertion sont triées** : la ligne
  d'erreur du protocole de l'agent et la ligne de la fonction publique
  `maelys_git_protocol_write_decision`.

Les reçus ne changent pas. Un corpus de 38 sorties enregistré avec la
version précédente (`tests/fixtures/json-corpus/`) est rejoué à chaque
exécution de la suite ; il n'admet que ces différences.

## Écritures

Toutes passent par [`src/common/json_write.c`](../src/common/json_write.c)
(`mg_json_begin` pour un usage nommé), sauf les reçus et leurs lignes JSONL,
écrits par [`src/receipt/receipt.c`](../src/receipt/receipt.c), et le
résultat que l'agent publie sans texte d'explication, réécrit par
[`src/agent/store.c`](../src/agent/store.c) : ces écritures étaient déjà en
maelys-json et ne changent pas. Chaque writer reçoit ses trois limites,
toutes non nulles ; le test de garde le vérifie pour chaque appel de
`maelys_json_writer_create`. Un appel invalide
fait échouer tout le document : le module garde la première erreur, ce que
maelys-json ne fait pas pour une erreur d'argument.

| Usage | Octets | Profondeur | Valeurs | Présentation |
|---|---|---|---|---|
| `MG_JSON_DATA`, données d'une commande CLI | plafond de la bibliothèque, `SIZE_MAX / 2 - 1` | 32 | plafond, `SIZE_MAX / 256` | ASCII, compacte |
| `MG_JSON_PROTOCOL_LINE`, résultat, événement, erreur, décision | 65 536 octets de JSON, séparateur exclu | 32 | 32 768 | ASCII, compacte, LF écrit après |
| `MG_JSON_DEDUPLICATION`, forme v2 | 65 536 | 32 | 32 768 | ASCII, compacte, sans LF |
| `MG_JSON_CONFIGURATION`, configuration générée | 65 536, comme son lecteur | 1 | 29 | indentée, LF écrit après |
| reçu (`receipt.c`) | 8 192 au plus (`MAELYS_GIT_RECEIPT_MAX_BYTES`) | 4 | 512 | canonique, sans drapeau |
| ligne JSONL d'un reçu et de son texte (`receipt.c`) | reçu, plus six fois le texte de 32 768 octets, plus 256 | 5 | 520 | UTF-8, LF final compté |
| résultat publié sans texte (`store.c`) | 65 536 | 32 | 32 768 | UTF-8 non échappé, compacte |

**Données CLI : aucune limite nouvelle.** Le changement de bibliothèque
n'ajoute aucune limite applicative. Les sorties bornées par leur contrat le
restent : `repo list` à 10 000 entrées, les conflits de `pr check` et
`pr merge` à 128 chemins, `migrate gitolite` à 1 024 entrées non migrables
(environ 28 Mio dans le pire cas, chaque octet de contrôle valant six octets
échappés). `repo diff` n'a pas de borne contractuelle : sa liste de chemins
n'est bornée que par la mémoire, comme avant. La seule limite réelle est la
profondeur ; le schéma de sortie le plus profond imbrique quatre conteneurs,
et `test-maelys-git-cli` vérifie qu'aucun schéma ne dépasse 32.

**Protocole : la ligne de 65 536 octets.** Le lecteur appliquait déjà cette
limite ; l'exécuteur l'applique maintenant à l'émission. Un résultat qui la
dépasserait devient un résultat `failed`, de code `limit_exceeded`, corrélé
à sa commande et écrit en entier sur une ligne ; le flux continue avec la
commande suivante. Une décision dont le texte d'explication fait dépasser la
ligne est d'abord réécrite, dans un nouveau writer, sans `explanation_text`,
son reçu inchangé : l'empreinte du texte reste dans le reçu.

## Lectures aux frontières de confiance

| Module et opération actuelle | Origine et état actuel | Cible et couture |
|---|---|---|
| [`src/agent/config.c`](../src/agent/config.c), `mg_config_load` | **Migré** : fichier ouvert une fois, contrôlé par `fstat` puis lu sur ce descripteur ; parse maelys-json limité à 65 536 octets, profondeur 1 et 31 valeurs. | Validation des 14 champs scalaires requis et de `grants_path`, optionnel, des chemins et des plages numériques ; copie dans `maelys_git_agent_config_t`, puis libération du document. |
| [`src/protocol/protocol.c`](../src/protocol/protocol.c), `mg_protocol_parse` | **Migré** : maelys-json `RFC8259`, 65 536 octets, profondeur 32, 32 768 tokens ; validation de l’enveloppe et des horodatages entiers signés sur 64 bits. | Le message possède ensemble le document et le handle `maelys_json_value_t` du payload. Les lectures typées de l’exécuteur utilisent ce document jusqu’à `mg_protocol_message_clear` ; aucune vue empruntée ne lui survit. |
| [`src/agent/agent.c`](../src/agent/agent.c), `maelys_git_agent_serve` | **Migré** : cadrage borné par comptage d’octets ; le parseur reçoit la longueur exacte, NUL compris. | 65 536 octets de JSON, hors un LF ou CRLF final obligatoire. Ligne malformée complète : erreur puis poursuite ; dépassement ou ligne non terminée : erreur et arrêt du flux. |
| [`src/agent/cloud.c`](../src/agent/cloud.c), `poll_commands` / `process_command` | **Migré** : parse maelys-json du corps HTTP exact, 65 536 octets, profondeur 34 et 32 768 tokens ; schéma du lot et domaine numérique contrôlés avant la boucle. | 32 commandes au plus, curseur inférieur à 1 024 octets. La forme de déduplication v2 de chaque commande est écrite depuis ce document ; chaque commande possède ensuite son document, vérifie son destinataire et suit ses propres validations. Le document du lot garde le curseur vivant jusqu’à sa persistance. |
| [`src/agent/supervisor.c`](../src/agent/supervisor.c), `mg_supervisor_execute`, puis persistance dans `cloud.c` | **Migré** : une réponse JSONL, 65 536 octets de JSON hors LF/CRLF, profondeur 32 et 32 768 tokens ; parse maelys-json et validation de l’enveloppe. | Corrélation obligatoire de `message_id`, `agent_id` et `command`, protocole/type exacts, statut `ok`/`denied`/`failed`, payload objet. Le statut validé est transmis sans relecture. Une réponse invalide devient un échec local corrélé ; son contenu n’est pas persisté. Les résultats du journal sont revalidés avant remise en file. |
| [`src/policy/policy.c`](../src/policy/policy.c), `collect_manifest_atoms` / chargement du jeu | Manifeste externe ; prélecture limitée à 1 Mio avec **yyjson**, puis nouvelle ouverture par `maelys_datalog_manifest_load_ex`. | Traiter cette frontière avec maelys-datalog : le chargeur effectif et la collecte des atomes doivent consommer le même contenu validé. Une prévalidation maelys-json suivie d'une réouverture indépendante ne suffit pas. Conserver la sélection `enabled` et les contrôles de chemins et d'intégrité. |

La validation du payload par commande se trouve dans
[`src/agent/executor.c`](../src/agent/executor.c). Ces lecteurs sont désormais
migrés avec le protocole. Valider seulement l'enveloppe ne rend pas fiable
le sous-arbre `payload`.

Le couple document/handle est indissociable : un handle n'est ni une référence
comptée ni une valeur autonome. Le message garde son document vivant pendant
toute l'exécution ; sa libération invalide les handles et les vues empruntées.
Le lot Cloud possède son propre document jusqu’à la fin de la boucle et de la
persistance du curseur emprunté. Chaque commande reparsée possède un document
indépendant ; la libération d’une commande n’invalide pas le curseur du lot.
Le superviseur libère son document après avoir matérialisé le statut validé et
conserve les octets JSON originaux de la réponse, sans terminateur.

Pour la configuration, la séquence implémentée est ouverture avec les protections
adaptées contre les liens symboliques, `fstat` du descripteur, vérification du
type, du propriétaire et des permissions, lecture bornée sur ce descripteur,
puis parse du tampon avec sa longueur exacte. `parse_file` rouvrirait le chemin
et séparerait de nouveau le contrôle de la lecture ; il ne convient pas à cette
séquence. L'ouverture est non bloquante afin de pouvoir refuser un FIFO avant
toute lecture. Les trois limites sont explicites : 65 536 octets, profondeur
1 et 31 valeurs (la racine, 15 clés et 15 scalaires : les 14 champs requis et
`grants_path`, optionnel depuis GIT-C06). Une configuration valide
d'exactement 65 536 octets reste acceptée, blancs compris ; un octet de plus
est refusé. Les champs numériques sont lus comme entiers sans fraction ni
exposant, puis contrôlés : `version` vaut 1, les deux délais sont compris entre
1 000 et 120 000 ms. Les contrôles des fichiers référencés restent applicables.

Pour les commandes, les accesseurs `i64` maintiennent le domaine signé existant :
horodatages et quotas strictement positifs, compteurs d’approbations positifs ou
nuls, aucun lexème fractionnaire ou exponentiel. Les booléens exigent leur type
exact. Les chaînes facultatives présentes doivent être non vides conformément
au schéma, y compris les préconditions reçues en mode plan ; les types erronés
ne sont plus assimilés à une absence. La profondeur 32 admet tous les payloads
actuellement définis (au plus trois conteneurs imbriqués). Les tests couvrent
9 000 valeurs, les tailles et profondeurs limites, la propriété des documents,
les deux flux JSONL et la reprise du journal avec les clés U+E000/U+10000.
Le parseur d’enveloppe seul ne valide pas le schéma du payload.

Pour les manifestes, l'intégration doit coordonner les lectures et le parseur
réel de la dépendance, par exemple via une interface consommant les mêmes
octets validés. Les fichiers Datalog référencés gardent leurs propres contrôles
de lecture et d'intégrité ; leur grammaire n'est pas du JSON.

## Forme de déduplication v2 et migration du journal

La clé d'idempotence du journal est `message_id`, stockée dans `commands.id`.
`commands.raw_json` est son témoin de contenu : pour un identifiant existant,
`mg_store_record_command` exige l'égalité des octets par `strcmp`.

La **forme v2** est la commande réécrite par maelys-json depuis le document
validé, avec l'usage `MG_JSON_DEDUPLICATION` : compacte, ASCII (`\u` en
minuscules), clés dans l'ordre RFC 8785, sans LF final. La forme v1 des
versions précédentes triait les clés par octets UTF-8 et écrivait ses
échappements en majuscules : pour une même commande, les deux formes
diffèrent dès qu'un payload contient un caractère échappé ou des clés dont
les deux ordres divergent (par exemple U+E000 et U+10000).

Le journal enregistre sa forme dans `metadata('dedup_form')`. À l'ouverture,
dans une seule transaction `BEGIN IMMEDIATE` :

1. une forme inconnue fait refuser l'ouverture ; le marqueur est comparé
   sur ses octets exacts, si bien qu'un `v2` suivi d'autres octets, NUL
   compris, ou qui n'est pas du texte, est inconnu ;
2. un journal sans marqueur est en v1 : chaque `raw_json` est relu et
   réécrit en v2 ; une ligne qui ne se convertit pas fait refuser l'ouverture
   en nommant sa commande ;
3. le marqueur `v2` est inscrit ;
4. les commandes `running` reviennent à `pending`.

Un échec annule tout : le journal reste tel qu'il était. Un journal neuf naît
en v2. Les commandes terminées gardent leur résultat et ne sont pas
réexécutées. **Le retour à un binaire antérieur n'est pas supporté** : il
comparerait des formes v1 aux lignes v2 du journal et refuserait les
commandes rejouées comme des réutilisations de `message_id`.

Ce contrat reste distinct de Maelys Canonical JSON v1, utilisé pour les
reçus : la forme v2 est échappée en ASCII, les octets canoniques ne le sont
pas. Ne jamais comparer un reçu au `raw_json` du journal.

## Octets hachés ou signés

Les [reçus d'autorisation](prepared-auth-receipts.md) sont écrits par un
writer maelys-json dédié, alimenté par une structure C matérialisée. Le hash
porte sur sa sortie canonique sans drapeau de présentation ni LF final.
L'enveloppe du résultat contient le reçu et son empreinte, tandis que
l'audit conserve les octets canoniques originaux.

Pour vérifier un reçu canonique reçu sous forme brute :

1. Conserver les octets d'entrée et leur longueur exacte ; les parser avec
   `maelys_json_document_parse`, le profil `RFC8259` et les limites du reçu,
   puis valider son schéma et ses plages numériques.
2. Appeler `maelys_json_document_is_canonical(document, 0, &is_canonical)` et
   exiger à la fois `MAELYS_JSON_OK` et `is_canonical != 0`. Une erreur ou une
   entrée non canonique est refusée, sans tentative de la normaliser.
3. Hacher les **octets d'entrée** validés, sans les réémettre, puis comparer
   l'empreinte attendue ou vérifier la signature selon le contrat applicable.

Le drapeau `0` impose notamment l'absence de LF final. Un objet réémis dans
une enveloppe, notamment avec le drapeau `ASCII` d'une ligne du protocole, est
une vue de présentation : le vérificateur le réécrit sous forme canonique
avant de le hacher, et l'audit garde les octets canoniques.

Les empreintes existantes ne sont pas à réécrire dans ce chantier :

- `policy.c` délègue l'empreinte du jeu à
  `maelys_datalog_policy_set_fingerprint` ; conserver ce contrat.
- [`mirror.c`](../src/repository/mirror.c) hache les références Git et l'état
  de HEAD selon son propre format ; ce flux n'est pas du JSON.
- [`pull_request.c`](../src/repository/pull_request.c) produit des objets
  commit via `git hash-object` ; conserver le format Git.
- `gitolite.c` hache le texte de politique, comme indiqué plus haut.

## Conditions maintenues

1. Fixer les trois limites de chaque lecteur et de chaque writer, sans
   hériter des valeurs par défaut de la bibliothèque (65 535 octets,
   profondeur 32, 8 192 valeurs). Préciser séparément les octets du JSON et
   ceux du terminateur JSONL. Un document JSON de `T` valeurs nécessite au
   moins `2*T - 1` octets : 32 768 valeurs suffisent à 65 536 octets.
2. Une nouvelle écriture prend un usage de `json_write.c`, ou en ajoute un
   avec ses limites ; une nouvelle forme durable prend sa propre version et
   une migration explicite.
3. Valider chaque frontière sur les entrées légitimes et les refus attendus :
   doublons après décodage, UTF-8/BOM/U+0000, fractions et exposants, bornes
   entières, profondeur, nombre de valeurs, tailles limites et suffixes après
   le document.
4. Le manifeste de policy reste lu par maelys-datalog ; sa coordination avec
   un lecteur maelys-json est un chantier distinct.

## Historique

- **2026-09-05.** Inventaire établi sur `4024956` (`v0.1.0`), maelys-json
  `v0.1.3`. Décision : maelys-json pour les lectures aux frontières de
  confiance et pour les octets hachés ou signés ; Jansson conservé pour les
  arbres internes, les réponses, les données CLI, la configuration générée
  et la forme de déduplication v1, avec un adaptateur qui relisait les mêmes
  octets validés. La coexistence était déclarée durable.
- **2026-10-18 (GIT-C05).** Coexistence révoquée : Jansson retiré, toutes
  les écritures passent à maelys-json `v0.3.0`, la forme de déduplication
  passe en v2 avec migration du journal, et l'exécuteur borne ses résultats à
  la ligne du protocole.
