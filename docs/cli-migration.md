# Migration vers le contrat CLI normalisé

## Passage au framework maelys-cli

Depuis cette version, les cinq binaires sont construits sur `libmaelys_cli`
(dépôt `maelys-cli`). Le contrat `agent-cli/v2` est inchangé : mêmes
enveloppes, mêmes codes d'erreur, mêmes codes de sortie, mêmes identifiants
de commandes et mêmes schémas de `data`. Les différences visibles sont :

| Avant | Après |
| --- | --- |
| `describe` : `outputMode` valait `git-smart-protocol-stream`, `git-hook-stream`, `maelys-git-agent-jsonl-stream` ou `maelys-git-events-jsonl-stream` | `outputMode: "protocol-stream"` et un champ `protocol` (`git-smart`, `git-hook`, `maelys-git-agent/1`, `maelys-git-events/1`) |
| `describe` : `globalOptions` était un objet | tableau de descripteurs d'options, comme `input.options` |
| `describe` : `argument.type` limité à `string`, `integer`, `path`, `oid`, `sha256` | `unsigned`, `size`, `choice` (avec `choices`), `hex` (avec `digits`), bornes `minimum`/`maximum`, `default` |
| `describe` et `version` : `product`, `version` | ajout de `program`, `framework` (version de `libmaelys_cli`) et `cliApi` ; `describe` ajoute `external`, `hidden`, `passthrough` |
| `help` global seulement | `help COMMAND_ID`, `COMMAND --help`, `-h` |
| erreur texte `Maelys error [CODE] (commande): message` | `PROGRAMME: [CODE] message` puis `Hint: …` |
| `--style`, `--from` : chaînes vérifiées par le gestionnaire | choix (`ff\|merge\|squash`, `archive\|trash`) vérifiés avant exécution |
| `--approvals`, `--required-approvals`, `--max-*` : entiers signés | non signés ; une valeur négative est refusée (`--approvals -1` passait auparavant la barrière d'approbations) |
| `--max-total-blob-bytes`, `--max-inspected-blob-bytes`, `--max-source-bytes` : octets | acceptent aussi les suffixes `K`, `M`, `G`, `T` |
| `--expected-*-fingerprint`, `--expected-prepared-oid` : vérifiés par le gestionnaire | `hex` de 64 ou 40/64 chiffres vérifié par l'analyseur |
| `authorize` : `data.matchedPolicy` valait `-1` sans politique correspondante (contraire au schéma) | `null` |
| `describe` : dépendances `--apply` ↔ préconditions exprimées en chaîne de `requires` | une contrainte `all-or-none` (groupe `apply`) par transaction ; `input.options[].group` |
| `describe` : `available` absent | `available` et `unavailableReason` (`maelys-git-agent run` sans Cloud) |
| opérandes OID (`OLD_OID`, `NEW_OID`, `BASE_OID`, `HEAD_OID`) : texte vérifié par le gestionnaire | `hex` de 40 ou 64 chiffres minuscules, vérifié par l'analyseur (`argument.type` de l'opérande) |
| `--git`, `keys compile SHELL ROOT MANIFEST`, options de chemin de `provision` : chaînes | `absolute-path` ; un chemin relatif est refusé avant exécution |
| `--max-*` : défaut appliqué par le gestionnaire | `default` exposé par `describe` et livré par le framework |
| — | `--color auto\|always\|never`, `--` pour terminer les options, `--format jsonl` réservé aux commandes à enregistrements, `MAELYS_CLI_FORMAT`, `PROGRAMME completion bash\|zsh\|fish` |

Les scripts qui lisent `outputMode` doivent comparer à `protocol-stream` et
lire `protocol` ; ceux qui lisent `globalOptions` doivent itérer sur un tableau,
présent seulement dans les formes d'inventaire de `describe`.
Rien d'autre ne change pour une automatisation conforme (`--format json`,
`error.code`, `data`).

## Formes préliminaires

La normalisation rend explicite la différence entre une commande de contrôle et
un flux Git/JSONL. Les anciennes formes préliminaires sont remplacées ainsi :

| Ancienne invocation | Invocation normalisée |
| --- | --- |
| `maelys-git-shell --user …` | `maelys-git-shell serve --user …` |
| `maelys-git-hook --mode pre-receive …` | `maelys-git-hook pre-receive …` |
| `maelys-git-hook --mode post-receive …` | `maelys-git-hook post-receive …` |
| `maelys-git-executor --manifest …` | `maelys-git-executor serve --manifest …` |
| `maelys-git repo init ROOT REPO [GIT]` | `maelys-git repo init ROOT REPO [--git FILE] [--apply]` |
| `maelys-git repo diff … [GIT]` | `maelys-git repo diff … [--git FILE]` |
| `maelys-git repo update-ref … [GIT]` | `maelys-git repo update-ref … [--git FILE] [--apply]` |
| `maelys-git-agent provision …` | même forme, plan par défaut ; ajouter `--apply` pour écrire |

Une ancienne automatisation qui analysait le JSON métier brut doit ajouter
`--format json` et lire ce JSON sous `data`. Elle doit lire les erreurs sur
stderr, vérifier `contract`, puis utiliser `error.code` plutôt que comparer le
texte du diagnostic.

Les wrappers `authorized_keys` et hooks doivent être mis à jour avant de
remplacer les binaires. Le superviseur inclus lance déjà l'exécuteur avec le
nouveau verbe `serve`.
