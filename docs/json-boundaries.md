# Frontières JSON : maelys-json et Jansson

Décision d'architecture du 2026-09-05. Inventaire initial du code git-core établi sur
`4024956` (`v0.1.0`). Le contrat maelys-json et la cible d'intégration sont ceux
du tag **`v0.1.3`**, version `0.1.3`, résolu au commit
`0e60ec313388957739968a69c6a78c323b9dd67d`.
Trois lots implémentés : git-core épingle cette révision pour la configuration
(lue sur le descripteur contrôlé), les enveloppes de commande, les lectures
typées de payload, les lots Cloud et la validation des réponses du superviseur.
Le manifeste et les reçus restent à migrer selon le découpage ci-dessous. Jansson construit toujours les réponses et la configuration, et
produit la forme de déduplication v1.

## Décision

maelys-json sert à lire les entrées JSON externes avec des limites explicites
et à produire les octets JSON dont dépend une empreinte ou une signature.
Jansson reste adapté aux arbres internes mutables et à la construction des
enveloppes, réponses et sorties CLI ordinaires. Leur coexistence est durable :
la suppression de Jansson et la réécriture générale des `json_pack` ne sont
pas des objectifs.

Le choix porte sur une opération, pas sur un fichier entier. Un même module
peut lire avec maelys-json, matérialiser des valeurs C validées, puis construire
sa réponse avec Jansson. Un document syntaxiquement valide n'est pas encore
une commande autorisée : schéma, plages numériques, chemins, identité,
expiration et politique restent à vérifier avant son utilisation.

## Deux modèles, et le contrat effectivement disponible

Jansson fournit des arbres mutables à comptage de références, avec partage de
sous-arbres et construction par `json_pack`. maelys-json fournit un document
immuable et un writer qui construit puis sérialise un nouvel arbre ; les
modifications passent par la recopie des membres conservés avec
`maelys_json_writer_value` et l'écriture des membres remplacés.

La version retenue de maelys-json impose les précisions suivantes :

- Le parseur accepte les lexèmes numériques JSON, y compris fractions et
  exposants. Les accesseurs entiers et la sérialisation canonique les refusent.
  Un contrat « entiers seulement » exige donc une validation typée explicite.
  Le domaine entier du writer va de `INT64_MIN` à `UINT64_MAX` ; cela
  n'élargit pas automatiquement les champs existants de git-core.
- L'accès par indice et les étapes d'itération sont en O(1) ; la recherche
  d'un membre par clé est en O(n).
- Le profil `RFC8259` convient aux chemins, principaux et textes Unicode.
  `CONTRACT_ASCII` convient seulement aux contrats qui restreignent
  explicitement leurs chaînes à sa forme ASCII sans échappement. Aucun des
  deux profils n'impose à lui seul une entrée canonique.
- Les limites portent sur les octets, la profondeur et le nombre de valeurs,
  clés comprises au parse. Les doublons décodés, U+0000, BOM, UTF-8 invalide
  et substituts Unicode isolés sont refusés.
- Le writer trie toujours les clés selon leurs unités UTF-16 non échappées.
  `JSON_SORT_KEYS | JSON_COMPACT` de Jansson ne garantit donc pas les mêmes
  octets pour toutes les clés Unicode. Les drapeaux maelys-json `INDENT`
  (deux espaces) et `ASCII` produisent des formes de présentation,
  distinctes des octets canoniques à hacher ou signer.

Sources du contrat : [API maelys-json](../../maelys-json/include/maelys/json.h),
[format canonique](../../maelys-json/docs/canonical-json-v1.md) et
[intégration](../../maelys-json/docs/integration.md), aux révisions indiquées
ci-dessus. Le CMake, la cible `maelys::json`, `writer_value`,
`maelys_json_document_is_canonical`, les drapeaux de présentation, les tests
du writer et son harnais de fuzz existent déjà. Ce découpage ne demande pas
de nouvelle API dans maelys-json.

## Lectures aux frontières de confiance

| Module et opération actuelle | Origine et état actuel | Cible et couture |
|---|---|---|
| [`src/agent/config.c`](../src/agent/config.c), `mg_config_load` | **Migré** : fichier ouvert une fois, contrôlé par `fstat` puis lu sur ce descripteur ; parse maelys-json limité à 65 536 octets, profondeur 1 et 29 valeurs. | Validation des 14 champs scalaires requis, des chemins et des plages numériques ; copie dans `maelys_git_agent_config_t`, puis libération du document. Writer de configuration conservé en Jansson. |
| [`src/protocol/protocol.c`](../src/protocol/protocol.c), `mg_protocol_parse` | **Migré** : maelys-json `RFC8259`, 65 536 octets, profondeur 32, 32 768 tokens ; validation de l’enveloppe et des horodatages entiers signés sur 64 bits. | Le message possède ensemble le document et le handle `maelys_json_value_t` du payload. Les lectures typées de l’exécuteur utilisent ce document jusqu’à `mg_protocol_message_clear` ; aucune vue empruntée ne lui survit. |
| [`src/agent/agent.c`](../src/agent/agent.c), `maelys_git_agent_serve` | **Migré** : cadrage borné par comptage d’octets ; le parseur reçoit la longueur exacte, NUL compris. | 65 536 octets de JSON, hors un LF ou CRLF final obligatoire. Ligne malformée complète : erreur puis poursuite ; dépassement ou ligne non terminée : erreur et arrêt du flux. |
| [`src/agent/cloud.c`](../src/agent/cloud.c), `poll_commands` / `process_command` | **Migré** : parse maelys-json du corps HTTP exact, 65 536 octets, profondeur 34 et 32 768 tokens ; schéma du lot et domaine numérique contrôlés avant la boucle. | 32 commandes au plus, curseur inférieur à 1 024 octets. Adaptateur transitoire Jansson sur les mêmes octets pour la déduplication v1 ; chaque commande possède ensuite son document, vérifie son destinataire et suit ses propres validations. Le document du lot garde le curseur vivant jusqu’à sa persistance. |
| [`src/agent/supervisor.c`](../src/agent/supervisor.c), `mg_supervisor_execute`, puis persistance dans `cloud.c` | **Migré** : une réponse JSONL, 65 536 octets de JSON hors LF/CRLF, profondeur 32 et 32 768 tokens ; parse maelys-json et validation de l’enveloppe. | Corrélation obligatoire de `message_id`, `agent_id` et `command`, protocole/type exacts, statut `ok`/`denied`/`failed`, payload objet. Le statut validé est transmis sans relecture Jansson. Une réponse invalide devient un échec local corrélé ; son contenu n’est pas persisté. Les résultats du journal sont revalidés avant remise en file. |
| [`src/policy/policy.c`](../src/policy/policy.c), `collect_manifest_atoms` / chargement du jeu | Manifeste externe ; prélecture limitée à 1 Mio avec **yyjson**, puis nouvelle ouverture par `maelys_datalog_manifest_load_ex`. | Traiter cette frontière avec maelys-datalog : le chargeur effectif et la collecte des atomes doivent consommer le même contenu validé. Une prévalidation maelys-json suivie d'une réouverture indépendante ne suffit pas. Conserver la sélection `enabled` et les contrôles de chemins et d'intégrité. |

La validation du payload par commande se trouve dans
[`src/agent/executor.c`](../src/agent/executor.c). Ces lecteurs sont désormais
migrés avec le protocole ; les constructeurs de résultats du même fichier
restent en Jansson. Valider seulement l'enveloppe ne rend pas fiable
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
1 et 29 valeurs (la racine, 14 clés et 14 scalaires). Une configuration valide
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

## Construction interne et stockage

| Module ou surface | Décision |
|---|---|
| `config.c`, génération d'une configuration neuve | Garder `json_pack` et la sortie indentée Jansson. Une configuration produite localement repasse par la validation lors d'un chargement ultérieur. |
| `protocol.c`, encodage des résultats et événements ; `agent.c`, erreurs de protocole | Garder les constructeurs Jansson. Ces enveloppes ne sont pas actuellement des documents JSON signés. |
| `executor.c`, résultats d'autorisation, dépôts et PR ; `cloud.c`, erreur d'exécuteur | Garder les arbres Jansson construits depuis les résultats C validés. |
| [`src/cli/admin.c`](../src/cli/admin.c), [`src/cli/agent.c`](../src/cli/agent.c), [`src/cli/json_support.c`](../src/cli/json_support.c) | Garder Jansson pour les données de réponse ; le framework maelys-cli conserve ses responsabilités de rendu et de contrat. Aucun remplacement général des `json_pack`. |
| [`src/agent/store.c`](../src/agent/store.c), journal, audit et outbox SQLite | Le module stocke des chaînes, sans parse JSON. Valider à l'entrée et à toute réinterprétation ; un passage par SQLite ne crée pas une garantie de confiance. Conserver exactement les octets d'un futur reçu canonique. |
| [`include/maelys_git_cli.h`](../include/maelys_git_cli.h) | N'expose déjà plus `json_t`. Les usages restants se trouvent dans les en-têtes internes de l'agent et du support JSON CLI ; aucune migration de cet en-tête public n'est requise. |
| [`src/hooks/pre_receive.c`](../src/hooks/pre_receive.c), événements post-receive | L'écriture JSONL actuelle est manuelle, sans Jansson. Le writer des futurs reçus peut aussi remplacer cet échappeur dans le chantier des reçus ; le seul fait d'émettre du JSON ne l'impose pas. |
| [`src/repository/gitolite.c`](../src/repository/gitolite.c), génération du manifeste | Le SHA-256 porte sur le texte de politique Datalog, puis est inséré dans un manifeste JSON généré. Ce n'est pas un hachage du manifeste ; aucune migration de sérialisation n'est imposée par cette empreinte. |

Une adaptation transitoire vers Jansson est possible **après** validation
bornée du document et de son schéma. Dans tout le sous-arbre transféré, elle
doit refuser explicitement :

- tout entier hors de `[INT64_MIN, INT64_MAX]`, notamment un `uint64` supérieur
  à `INT64_MAX`, représentable par maelys-json mais pas par le Jansson utilisé
  ici ; les plages plus étroites du schéma continuent de s'appliquer ;
- toute fraction ou tout exposant, même `1.0` ou `1e0`, sans conversion ni
  arrondi vers un entier.

Le double parse est une transition admise : maelys-json valide d'abord, puis
Jansson relit **exactement le même tampon immuable et sa même longueur**, avec
`json_loadb` et `JSON_REJECT_DUPLICATES`. La première passe borne déjà sa taille,
sa profondeur et ses valeurs ; aucune réouverture ou nouvelle lecture externe
n'intervient. Sur ce sous-domaine validé (racine conforme au schéma, chaînes
acceptées, entiers signés représentables), le différentiel doit établir que
Jansson accepte les mêmes valeurs et les conserve. Une erreur de la seconde
passe reste un échec ; aucun repli ne contourne le premier parseur. La
propriété du nouvel arbre Jansson doit être explicite.

## Forme de déduplication v1, produite par Jansson

La clé d'idempotence du journal est `message_id`, stockée dans `commands.id`.
`commands.raw_json` est son témoin de contenu : pour un identifiant existant,
`mg_store_record_command` exige l'égalité des octets par `strcmp`.

Pour les commandes Cloud, la **forme de déduplication v1** est exactement la
sortie de `json_dumps(command, JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS)`
dans `process_command`, sans LF final. Elle conserve les échappements ASCII
de Jansson et son ordre de clés par `strcmp`. Les journaux existants gardent
cette représentation ; toute nouvelle normalisation comparée à leur `raw_json`
doit encore être produite par Jansson selon cette forme v1.

Ce contrat est distinct de Maelys Canonical JSON v1, utilisé pour les reçus.
Ne jamais comparer une sortie maelys-json à ce `raw_json`, même avec le drapeau
`ASCII` : l'ordre UTF-16 peut encore différer. Les valeurs JSON du témoin et
du reçu n'ont pas non plus le même rôle. Une future forme de déduplication
nécessiterait sa propre version et une migration explicite des journaux ;
l'introduction des reçus ne la déclenche pas.

Le lot Cloud implémente cet adaptateur : le schéma du lot et tous ses lexèmes
numériques sont validés avant la relecture Jansson des mêmes octets. Les
fractions, exposants et entiers hors du domaine signé 64 bits font refuser le
lot entier avant toute commande. Les enveloppes et payloads restent validés par
commande, et les constructeurs de résultats restent en Jansson.

Le superviseur valide l’enveloppe décrite dans
[`agent-result-v1.schema.json`](../protocol/agent-result-v1.schema.json), sans
interpréter les données métier du payload objet. Ses consommateurs doivent
encore valider ces données avant leur utilisation. La reprise d’un résultat
SQLite exige la même corrélation et un statut cohérent avec l’état du journal ;
un résultat absent ou invalide bloque sa remise en file et le curseur du lot.

## Octets hachés ou signés

Les [reçus d'autorisation proposés](prepared-auth-receipts.md) utiliseront un
writer maelys-json dédié, alimenté par une structure C matérialisée. Le hash
portera sur sa sortie canonique sans drapeau de présentation ni LF final.
L'enveloppe Jansson pourra contenir le reçu et son empreinte, tandis que
l'audit conservera les octets canoniques originaux.

Pour vérifier un reçu canonique reçu sous forme brute :

1. Conserver les octets d'entrée et leur longueur exacte ; les parser avec
   `maelys_json_document_parse`, le profil `RFC8259` et les limites du reçu,
   puis valider son schéma et ses plages numériques.
2. Appeler `maelys_json_document_is_canonical(document, 0, &is_canonical)` et
   exiger à la fois `MAELYS_JSON_OK` et `is_canonical != 0`. Une erreur ou une
   entrée non canonique est refusée, sans tentative de la normaliser.
3. Hacher les **octets d'entrée** validés, sans les réémettre, puis comparer
   l'empreinte attendue ou vérifier la signature selon le contrat applicable.

Le drapeau `0` impose notamment l'absence de LF final. Le transport des octets
bruts devra être défini avec les reçus pour permettre ce contrôle à réception ;
un objet réémis dans une enveloppe Jansson est une vue de présentation et ne
remplace pas ce flux. Ces reçus et leur hash ne sont pas encore implémentés.

Les empreintes existantes ne sont pas à réécrire dans ce chantier :

- `policy.c` délègue l'empreinte du jeu à
  `maelys_datalog_policy_set_fingerprint` ; conserver ce contrat.
- [`mirror.c`](../src/repository/mirror.c) hache les références Git et l'état
  de HEAD selon son propre format ; ce flux n'est pas du JSON.
- [`pull_request.c`](../src/repository/pull_request.c) produit des objets
  commit via `git hash-object` ; conserver le format Git.
- `gitolite.c` hache le texte de politique, comme indiqué plus haut.

## Conditions de mise en œuvre

1. **Épinglage réalisé pour la configuration et le protocole.** Retenir le tag
   maelys-json `v0.1.3` ; enregistrer la version `0.1.3` et son
   commit résolu `0e60ec313388957739968a69c6a78c323b9dd67d` dans
   [`cmake/dependencies.cmake`](../cmake/dependencies.cmake). Vérifier leur
   correspondance lors de l'intégration et utiliser le mécanisme existant
   d'export de ce commit, sans prendre un commit intermédiaire du dépôt frère.
   Lier les cibles concernées à `maelys::json` ; Jansson reste une dépendance
   des cibles qui le consomment.
2. Fixer les trois limites pour chaque lecteur et writer. Ne pas hériter
   silencieusement des valeurs par défaut (65 535 octets, profondeur 32,
   8 192 valeurs) : le protocole admet 65 536 octets et la prélecture du
   manifeste 1 Mio. Préciser séparément les octets du JSON et ceux du
   terminateur JSONL ; qualifier toute nouvelle limite de structure ou de
   configuration sur les contrats existants. La configuration v1 utilise
   maintenant les limites de son objet plat décrites ci-dessus. Le protocole
   utilise 65 536 octets hors terminateur, profondeur 32 et 32 768 tokens.
   Le lot Cloud entier utilise `maximum_tokens` à **32 768**, clés et
   conteneurs compris, avec une profondeur de **34** (objet et tableau du lot
   autour des 32 niveaux de commande). Les résultats utilisent profondeur 32
   et le même budget de tokens. Cette borne
   conservatrice découle du plafond de 65 536 octets : un document JSON de
   `T` tokens nécessite au moins `2*T - 1` octets, donc
   `T <= floor((65 536 + 1) / 2)`. Le nombre de commandes (32) ne borne pas à
   lui seul les valeurs de leurs payloads avant validation. Ne pas appliquer
   le défaut de 8 192 au lot ; qualifier la profondeur séparément et couvrir
   les lots dépassant 8 192 valeurs dans les tests de migration.
3. **Lectures configuration, protocole, Cloud et superviseur réalisées** :
   propriété des documents, payloads et validation des enveloppes de résultat
   sont traités avec leurs lecteurs.
   Coordonner le chantier manifeste avec le chargeur maelys-datalog.
4. Préserver la clé `message_id` et la **forme de déduplication v1, produite
   par Jansson** définie ci-dessus. Tester la reprise des journaux existants,
   les échappements ASCII et les clés dont les ordres UTF-8/UTF-16 diffèrent.
   Les octets canoniques des reçus restent hors de cette comparaison.
5. Valider chaque frontière sur les entrées légitimes et les refus attendus :
   doublons après décodage, UTF-8/BOM/U+0000, fractions et exposants, bornes
   entières, profondeur, nombre de valeurs, tailles limites et suffixes après
   le document. Tester la durée de vie des couples document/handle, y compris
   les documents de lots, les deux transports, la lecture de configuration
   sur le descripteur contrôlé et la reprise SQLite. Pour l'adaptateur, couvrir
   `INT64_MIN`, `INT64_MAX`, `INT64_MAX + 1`, `UINT64_MAX`, les dépassements et
   les lexèmes `1.0`/`1e0`. Le différentiel doit vérifier l'égalité structurelle
   sur le domaine partagé et distinguer les rejets volontairement plus stricts.
6. Qualifier séparément les reçus avec les vecteurs canoniques, notamment le
   tri UTF-16, les entiers 64 bits, les limites du writer, le refus des reçus
   entrants non canoniques par `maelys_json_document_is_canonical` et la
   conservation des octets dans l'audit. Les signatures éventuelles restent
   un chantier distinct.
