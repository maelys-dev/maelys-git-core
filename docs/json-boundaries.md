# Frontières JSON : maelys-json et Jansson

Décision d'architecture du 2026-09-05. Inventaire du code git-core établi sur
`4024956` (`v0.1.0`). Le contrat maelys-json et la cible d'intégration sont ceux
du tag **`v0.1.3`**, version `0.1.3`, résolu au commit
`0e60ec313388957739968a69c6a78c323b9dd67d`.
Ce document fixe le découpage à mettre en œuvre ; il n'annonce aucune
migration de code. Git-core ne lie pas encore maelys-json.

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
| [`src/agent/config.c`](../src/agent/config.c), `mg_config_load` | Fichier de configuration ; contrôle par `lstat`, puis ouverture indépendante par `json_load_file` avec rejet des doublons. Pas de plafond explicite de taille à ce point. | Ouvrir une fois, vérifier les attributs et lire sur ce même descripteur, puis parser les octets bornés avec `maelys_json_document_parse`. Valider le schéma et copier dans `maelys_git_agent_config_t` ; conserver les contrôles de chemins et de plages. |
| [`src/protocol/protocol.c`](../src/protocol/protocol.c), `mg_protocol_parse` | Commande JSONL ou commande Cloud ; `json_loadb`, plafond de 65 536 octets, validation de l'enveloppe, conservation du `payload` par `json_incref`. | Le message possède ensemble le document et le handle `maelys_json_value_t` du payload, valide seulement avec ce document. L'exécuteur ne conserve aucun handle après libération du message. Une matérialisation typée peut remplacer ce couple. |
| [`src/agent/agent.c`](../src/agent/agent.c), `maelys_git_agent_serve` | Cadrage des lignes sur stdin, puis délégation au parseur de protocole. | Garder le cadrage borné et transmettre la longueur exacte. Faire refuser U+0000 et toute donnée après le JSON sans troncature par une opération de chaîne C. |
| [`src/agent/cloud.c`](../src/agent/cloud.c), `poll_commands` / `process_command` | Corps HTTP limité à 65 536 octets ; parse Jansson du lot, puis sérialisation et second parse de chaque commande. | Parser le lot avec maelys-json, avec un plafond de 32 768 valeurs pour tout le lot, et valider chaque commande. Conserver les limites du lot (32 commandes, curseur inférieur à 1 024 octets), la vérification de l'agent destinataire et la forme de déduplication v1. |
| [`src/agent/supervisor.c`](../src/agent/supervisor.c), `mg_supervisor_execute`, puis lecture de `status` dans `cloud.c` | Réponse d'un autre processus, bornée à 65 536 octets avant retrait du terminateur ; le superviseur ne vérifie actuellement que le JSON et la racine objet. | Parse maelys-json à la réception et validation de l'enveloppe de résultat, de sa corrélation avec la commande et de son statut avant persistance. Réutiliser ces données validées pour éviter une nouvelle lecture moins stricte dans le Cloud. |
| [`src/policy/policy.c`](../src/policy/policy.c), `collect_manifest_atoms` / chargement du jeu | Manifeste externe ; prélecture limitée à 1 Mio avec **yyjson**, puis nouvelle ouverture par `maelys_datalog_manifest_load_ex`. | Traiter cette frontière avec maelys-datalog : le chargeur effectif et la collecte des atomes doivent consommer le même contenu validé. Une prévalidation maelys-json suivie d'une réouverture indépendante ne suffit pas. Conserver la sélection `enabled` et les contrôles de chemins et d'intégrité. |

La validation du payload par commande se trouve dans
[`src/agent/executor.c`](../src/agent/executor.c). Ces lecteurs appartiennent
à la migration du protocole, même si les constructeurs de résultats du même
fichier restent en Jansson. Valider seulement l'enveloppe ne rend pas fiable
le sous-arbre `payload`.

Le couple document/handle est indissociable : un handle n'est ni une référence
comptée ni une valeur autonome. Le message garde son document vivant pendant
toute l'exécution ; sa libération invalide les handles et les vues empruntées.
Si un handle pointe dans le document du lot Cloud, ce document doit lui aussi
rester vivant jusqu'à la fin de tous ses consommateurs, ou les données doivent
être copiées dans un document ou une structure possédés par le message.

Pour la configuration, la séquence cible est ouverture avec les protections
adaptées contre les liens symboliques, `fstat` du descripteur, vérification du
type, du propriétaire et des permissions, lecture bornée sur ce descripteur,
puis parse du tampon avec sa longueur exacte. `parse_file` rouvrirait le chemin
et séparerait de nouveau le contrôle de la lecture ; il ne convient pas à cette
séquence. Le code actuel n'applique pas encore cette vérification sur un même
descripteur.

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

1. Retenir le tag maelys-json `v0.1.3` ; enregistrer la version `0.1.3` et son
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
   configuration sur les contrats existants. Pour le lot Cloud entier, fixer
   `maximum_tokens` à **32 768**, clés et conteneurs compris. Cette borne
   conservatrice découle du plafond de 65 536 octets : un document JSON de
   `T` tokens nécessite au moins `2*T - 1` octets, donc
   `T <= floor((65 536 + 1) / 2)`. Le nombre de commandes (32) ne borne pas à
   lui seul les valeurs de leurs payloads avant validation. Ne pas appliquer
   le défaut de 8 192 au lot ; qualifier la profondeur séparément et couvrir
   les lots dépassant 8 192 valeurs dans les tests de migration.
3. Traiter ensemble le parseur de protocole, la propriété du document et
   les lecteurs de payload. Migrer la configuration indépendamment ; traiter
   les lectures Cloud et superviseur avec leur validation de résultat.
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
