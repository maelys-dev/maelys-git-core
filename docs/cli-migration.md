# Migration vers le contrat CLI normalisé

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
