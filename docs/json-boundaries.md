# Frontières JSON : maelys-json et Jansson

Décision d'architecture du 2026-09-05. Inventaire établi sur git-core
`4024956` (`v0.1.0`) et maelys-json `f0cb977` (`VERSION` : `0.1.2`).
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

La version locale de maelys-json impose les précisions suivantes :

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
ci-dessus. Le CMake, la cible `maelys::json`, `writer_value`, les drapeaux de
présentation, les tests du writer et son harnais de fuzz existent déjà.

## Lectures aux frontières de confiance

| Module et opération actuelle | Origine et état actuel | Cible et couture |
|---|---|---|
| [`src/agent/config.c`](../src/agent/config.c), `mg_config_load` | Fichier de configuration ; contrôle des permissions puis `json_load_file` avec rejet des doublons. Pas de plafond explicite de taille à ce point. | Parse borné maelys-json, validation du schéma et copie dans `maelys_git_agent_config_t`. Conserver les contrôles de fichiers, chemins et plages. |
| [`src/protocol/protocol.c`](../src/protocol/protocol.c), `mg_protocol_parse` | Commande JSONL ou commande Cloud ; `json_loadb`, plafond de 65 536 octets, validation de l'enveloppe, conservation du `payload` par `json_incref`. | Document maelys-json possédé par le message jusqu'à sa libération, ou matérialisation typée. Migrer les lectures du payload dans l'exécuteur avec cette durée de vie. |
| [`src/agent/agent.c`](../src/agent/agent.c), `maelys_git_agent_serve` | Cadrage des lignes sur stdin, puis délégation au parseur de protocole. | Garder le cadrage borné et transmettre la longueur exacte. Faire refuser U+0000 et toute donnée après le JSON sans troncature par une opération de chaîne C. |
| [`src/agent/cloud.c`](../src/agent/cloud.c), `poll_commands` / `process_command` | Corps HTTP limité à 65 536 octets ; parse Jansson du lot, puis sérialisation et second parse de chaque commande. | Parser le lot avec maelys-json et valider chaque commande. Conserver les limites du lot (32 commandes, curseur inférieur à 1 024 octets), la vérification de l'agent destinataire et le contrat d'idempotence. |
| [`src/agent/supervisor.c`](../src/agent/supervisor.c), `mg_supervisor_execute`, puis lecture de `status` dans `cloud.c` | Réponse d'un autre processus, bornée à 65 536 octets avant retrait du terminateur ; le superviseur ne vérifie actuellement que le JSON et la racine objet. | Parse maelys-json à la réception et validation de l'enveloppe de résultat, de sa corrélation avec la commande et de son statut avant persistance. Réutiliser ces données validées pour éviter une nouvelle lecture moins stricte dans le Cloud. |
| [`src/policy/policy.c`](../src/policy/policy.c), `collect_manifest_atoms` / chargement du jeu | Manifeste externe ; prélecture limitée à 1 Mio avec **yyjson**, puis nouvelle ouverture par `maelys_datalog_manifest_load_ex`. | Traiter cette frontière avec maelys-datalog : le chargeur effectif et la collecte des atomes doivent consommer le même contenu validé. Une prévalidation maelys-json suivie d'une réouverture indépendante ne suffit pas. Conserver la sélection `enabled` et les contrôles de chemins et d'intégrité. |

La validation du payload par commande se trouve dans
[`src/agent/executor.c`](../src/agent/executor.c). Ces lecteurs appartiennent
à la migration du protocole, même si les constructeurs de résultats du même
fichier restent en Jansson. Valider seulement l'enveloppe ne rend pas fiable
le sous-arbre `payload`.

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
bornée du document et de son schéma. Elle doit préserver les chaînes, les
types et les plages, refuser une conversion entière non représentable, et
définir la propriété des valeurs. Elle ne doit pas exposer de nouveau les
octets externes à un parse non borné ni transformer une fraction en entier.

## Octets hachés ou signés

Les [reçus d'autorisation proposés](prepared-auth-receipts.md) utiliseront un
writer maelys-json dédié, alimenté par une structure C matérialisée. Le hash
portera sur sa sortie canonique sans drapeau de présentation ni LF final.
L'enveloppe Jansson pourra contenir le reçu et son empreinte, tandis que
l'audit conservera les octets canoniques originaux. Une vérification devra
suivre ce même contrat de canonicalisation ; trier l'enveloppe avec Jansson
ne le remplace pas. Ces reçus et leur hash ne sont pas encore implémentés.

Les empreintes existantes ne sont pas à réécrire dans ce chantier :

- `policy.c` délègue l'empreinte du jeu à
  `maelys_datalog_policy_set_fingerprint` ; conserver ce contrat.
- [`mirror.c`](../src/repository/mirror.c) hache les références Git et l'état
  de HEAD selon son propre format ; ce flux n'est pas du JSON.
- [`pull_request.c`](../src/repository/pull_request.c) produit des objets
  commit via `git hash-object` ; conserver le format Git.
- `gitolite.c` hache le texte de politique, comme indiqué plus haut.

## Conditions de mise en œuvre

1. Épingler une version et un commit maelys-json dans
   [`cmake/dependencies.cmake`](../cmake/dependencies.cmake), selon le mécanisme
   existant d'export des sources, et lier les cibles concernées à
   `maelys::json`. Jansson reste une dépendance des cibles qui le consomment.
2. Fixer les trois limites pour chaque lecteur et writer. Ne pas hériter
   silencieusement des valeurs par défaut (65 535 octets, profondeur 32,
   8 192 valeurs) : le protocole admet 65 536 octets et la prélecture du
   manifeste 1 Mio. Préciser séparément les octets du JSON et ceux du
   terminateur JSONL ; qualifier toute nouvelle limite de structure ou de
   configuration sur les contrats existants.
3. Traiter ensemble le parseur de protocole, la propriété du document et
   les lecteurs de payload. Migrer la configuration indépendamment ; traiter
   les lectures Cloud et superviseur avec leur validation de résultat.
   Coordonner le chantier manifeste avec le chargeur maelys-datalog.
4. Préserver l'idempotence : `process_command` normalise aujourd'hui les
   commandes avec Jansson, et `mg_store_record_command` compare `raw_json`
   par `strcmp`. Un changement d'ordre Unicode ou d'échappement pourrait
   faire refuser une commande déjà journalisée sous le même identifiant.
   Conserver cette représentation pour les contrats actuels ou prévoir
   explicitement sa migration et la reprise des journaux existants.
5. Valider chaque frontière sur les entrées légitimes et les refus attendus :
   doublons après décodage, UTF-8/BOM/U+0000, fractions et exposants, bornes
   entières, profondeur, nombre de valeurs, tailles limites et suffixes après
   le document. Tester la durée de vie des payloads, les deux transports et
   la reprise SQLite. Un différentiel avec Jansson doit distinguer les
   invariants conservés des rejets volontairement plus stricts.
6. Qualifier séparément les reçus avec les vecteurs canoniques, notamment le
   tri UTF-16, les entiers 64 bits, les limites du writer et la conservation
   des octets dans l'audit. Les signatures éventuelles restent un chantier
   distinct.
