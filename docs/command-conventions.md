# Conventions des commandes Maelys Git Core

Ce document est normatif pour chaque commande publique de Maelys Git Core.
Les catalogues C de `src/cli/` (`admin.c`, `agent.c`, `shell.c`, `hook.c`)
et les schémas JSON de `schemas/` sont la source exécutable de vérité. Le
parseur, `help`, `version`, `describe`, le rendu des enveloppes et les codes
de sortie sont fournis par le framework partagé `libmaelys_cli`
(dépôt `maelys-cli`) ; ce dépôt ne contient aucun analyseur d'arguments ni
texte d'usage écrit à la main.

## Découverte

Un agent commence toujours par :

```sh
maelys-git describe --summary --format json --compact --non-interactive
maelys-git describe repo.init --format json --compact --non-interactive
```

Chaque descripteur expose un identifiant stable, `usage`, le même
`input.synopsis`, les opérandes, les options typées, les contraintes, l'effet,
le mode de sortie (`outputMode`, et `protocol` pour un flux), les codes de
sortie et le JSON Schema de `data`. L'inventaire porte aussi `program`,
`product`, `version`, `framework` (version de `libmaelys_cli`) et `cliApi`.

Une option publique doit être déclarée dans le catalogue avant son utilisation.
Une option inconnue, dupliquée ou appartenant à une autre commande est refusée.
La valeur d'une option reste une valeur même lorsqu'elle commence par `--` ;
`--` termine l'analyse des options.

## Types d'options

| Type `argument.type` | Déclaration | Validation |
| --- | --- | --- |
| `boolean` | `MAELYS_CLI_FLAG` | `--flag`, `--flag=true`, `--flag=false` |
| `string`, `path` | `MAELYS_CLI_STRING`, `MAELYS_CLI_PATH` | non vide |
| `absolute-path` | `MAELYS_CLI_ABSOLUTE_PATH` | non vide et commençant par `/` |
| `unsigned` | `MAELYS_CLI_UNSIGNED` | décimal dans `[minimum, maximum]` ; un signe est refusé |
| `size` | `MAELYS_CLI_SIZE` | octets avec suffixe optionnel `K`, `M`, `G`, `T` |
| `choice` | `MAELYS_CLI_CHOICE` | une des valeurs énumérées (`--style ff\|merge\|squash`) |
| `hex` | `MAELYS_CLI_HEX`, `MAELYS_CLI_HEX_OR` | hexadécimal minuscule de longueur fixe (SHA-256 : 64 ; OID : 40 ou 64) |

Les opérandes peuvent être typés de la même façon : les identifiants d'objets
sont des `hex` de 40 ou 64 chiffres (`MAELYS_GIT_CLI_OID_OPERAND`) et les
chemins d'administration durables des `absolute-path`
(`MAELYS_GIT_CLI_ABSOLUTE_OPERAND`, `MAELYS_CLI_ABSOLUTE_PATH`).

Les dépendances (`requires`), exclusions (`conflictsWith`) et groupes
tout-ou-rien (`group`, contrainte `all-or-none`) sont déclarés dans le
catalogue et vérifiés avant l'exécution du gestionnaire. Chaque transaction
place `--apply` et ses préconditions revues dans le groupe `apply` : un plan ne
porte jamais de précondition, un apply n'en manque jamais.

Une valeur par défaut est déclarée une seule fois, dans `default_text` ; elle
est validée contre le type au démarrage, exposée par `describe` (`default`) et
livrée par les accesseurs typés quand l'option est absente. Quand la
bibliothèque définit la constante (`MAELYS_GIT_DEFAULT_MAX_COMMITS`,
`MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_BYTES`, ...), le catalogue la déclare avec
`MAELYS_CLI_DEFAULT_OF` : une seule source, validée au démarrage.

## Effets

| Effet | Sémantique | Écriture durable |
| --- | --- | --- |
| `read` | Inspecte ou valide l'état. | Non |
| `preview` | Construit un plan exact. | Non |
| `apply` | Applique une transaction revue. | Oui |
| `execute` | Lance explicitement une action non transactionnelle. | Selon l'action |
| `stream` | Réserve stdin/stdout à un protocole déclaré. | Selon le protocole |

Une commande absente d'un build (par exemple `maelys-git-agent run` sans
agent Cloud) reste décrite avec `available: false` et `unavailableReason`, et
échoue avec `UNSUPPORTED`.

Une commande transactionnelle expose
`{"plan":"preview","apply":"apply"}`. Sans `--apply`, elle retourne
`mode: "plan"` et n'écrit rien. Avec `--apply`, elle revalide les préconditions
puis retourne `mode: "apply"`. `--dry-run` et `--plan` sont refusés : le plan
est déjà le comportement par défaut.

## Entrées

Les erreurs sont rapportées dans l'ordre causal suivant :

1. résolution de la commande ;
2. orthographe, duplication et appartenance des options ;
3. type et intervalle des valeurs ;
4. dépendances et conflits entre options ;
5. options requises, puis nombre des opérandes ;
6. contraintes de rendu (flux, `jsonl`) ;
7. type, permissions et lisibilité des fichiers ;
8. syntaxe puis schéma ;
9. politique, état courant et préconditions de concurrence.

Les six premières étapes sont exécutées par le framework avant tout
gestionnaire ; les suivantes appartiennent au gestionnaire et aux
bibliothèques du cœur.

Les chemins d'administration sont absolus lorsqu'ils deviennent une
configuration durable. Les secrets doivent être des fichiers réguliers non
symboliques, appartenir au compte agent et n'accorder aucun droit au groupe ou
au monde. Une cible d'écriture existante n'est jamais écrasée implicitement.

## Sorties

`--json` est l'alias exact de `--format json`. `--compact` et
`--pretty=false` sélectionnent une seule ligne sans changer le contrat.
`--non-interactive` garantit qu'aucune question ne sera posée. `--color`
contrôle les séquences ANSI du mode texte ; `--format jsonl` est réservé aux
commandes à enregistrements (aucune dans ce dépôt aujourd'hui). La variable
`MAELYS_CLI_FORMAT=json|text` fixe le rendu par défaut. `PROGRAMME completion
bash|zsh|fish` imprime une complétion générée depuis le catalogue.

Une réussite JSON va exclusivement sur stdout :

```json
{
  "schemaVersion": 2,
  "contract": "agent-cli/v2",
  "command": "repo.init",
  "ok": true,
  "exitCode": 0,
  "data": {}
}
```

Une erreur JSON va exclusivement sur stderr :

```json
{
  "schemaVersion": 2,
  "contract": "agent-cli/v2",
  "command": "repo.init",
  "ok": false,
  "exitCode": 1,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Diagnostic causal stable.",
    "hint": "Prochaine action sûre."
  }
}
```

En mode texte, une erreur s'écrit `PROGRAMME: [CODE] message` suivie d'une
ligne `Hint:` sur stderr.

Codes de processus : `0` pour une commande réussie, `1` pour une erreur
d'exécution, `2` pour une validation correctement exécutée qui a trouvé des
violations. Une décision d'autorisation négative reste une lecture réussie :
l'agent lit `data.allowed`, il ne déduit pas la décision du code de processus.

Codes d'erreur stables, et leur correspondance avec `maelys_git_result_t`
(`maelys_git_cli_fail_result`) :

| Code | Frontière | Résultats du cœur |
| --- | --- | --- |
| `INVALID_COMMAND` | Commande introuvable. | (framework) |
| `VALIDATION_FAILED` | Forme d'entrée, option, type ou limite invalide. | `INVALID_ARGUMENT`, `INVALID_COMMAND`, `INVALID_REPOSITORY`, `LIMIT` |
| `PRECONDITION_FAILED` | L'état a changé ou ne permet pas la transaction. | (gestionnaire) |
| `POLICY_FAILED` | Chargement ou évaluation Datalog impossible. | `POLICY` |
| `ACCESS_DENIED` | Décision de sécurité négative. | `DENIED` |
| `NOT_FOUND` | Ressource requise absente. | `NOT_FOUND` |
| `IO_FAILED` | Lecture ou écriture système échouée. | `IO` |
| `PROCESS_FAILED` | Sous-processus Git ou exécuteur échoué. | `PROCESS` |
| `PROTOCOL_FAILED` | Message ne respectant pas le protocole. | `PROTOCOL` |
| `UNSUPPORTED` | Fonction absente de ce build. | (gestionnaire) |
| `UNEXPECTED` | Défaut non classé à corriger dans l'implémentation. | tout autre |

## Flux protocolaires

Les commandes `stream` (`outputMode: "protocol-stream"`) sont les seules
exceptions à l'enveloppe :

| Commande | `protocol` |
| --- | --- |
| `maelys-git-shell serve` | `git-smart` : stdout appartient au smart protocol Git |
| `maelys-git-hook pre-receive` | `git-hook` : consomme le protocole de hook Git |
| `maelys-git-hook post-receive` | `maelys-git-events/1` : événements JSONL |
| `maelys-git-agent stdio`, `maelys-git-executor serve` | `maelys-git-agent/1` en JSONL |

Elles refusent les options de rendu JSON. Les diagnostics vont sur stderr sous
la forme `PROGRAMME OPÉRATION error [résultat]: message` et aucun texte
auxiliaire ne peut être injecté dans leur stdout.

## Preuve d'implémentation

Toute modification de commande doit mettre à jour dans le même changement :

1. l'entrée de catalogue et son gestionnaire dans `src/cli/` ;
2. le schéma de sortie `schemas/COMMAND.json` si sa forme change ;
3. les tests de catalogue, d'options et d'enveloppes (`tests/test_cli.c`,
   scripts d'intégration) ;
4. la référence générée par le générateur du framework
   (`maelys-cli-reference`, `cmake --build build --target
   generate-cli-reference`) ; le test `maelys-git-cli-docs` refuse toute
   dérive entre les binaires et `docs/`.

Le test de catalogue valide chaque application avec
`maelys_cli_catalog_validate` (identifiants uniques, résumés, types,
présence de `--apply` pour chaque transaction) et vérifie que chaque schéma
d'enveloppe interdit les propriétés inconnues et déclare ses champs requis.
