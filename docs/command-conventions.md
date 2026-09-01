# Conventions des commandes Maelys

Ce document est normatif pour chaque commande publique de Maelys Git Core. Le
catalogue C de `src/cli/catalog.c` est la source exécutable de vérité : le
parseur, `help`, `describe`, les tests et la référence générée en dépendent.

## Découverte

Un agent commence toujours par :

```sh
maelys-git describe --summary --format json --compact --non-interactive
maelys-git describe repo.init --format json --compact --non-interactive
```

Chaque descripteur expose un identifiant stable, `usage`, le même
`input.synopsis`, les opérandes, les options typées, les contraintes, l'effet,
le mode de sortie, les codes de sortie et le JSON Schema de `data`.

Une option publique doit être déclarée dans le catalogue avant son utilisation.
Une option inconnue, dupliquée ou appartenant à une autre commande est refusée.
La valeur d'une option reste une valeur même lorsqu'elle commence par `--`.

## Effets

| Effet | Sémantique | Écriture durable |
| --- | --- | --- |
| `read` | Inspecte ou valide l'état. | Non |
| `preview` | Construit un plan exact. | Non |
| `apply` | Applique une transaction revue. | Oui |
| `execute` | Lance explicitement une action non transactionnelle. | Selon l'action |
| `stream` | Réserve stdin/stdout à un protocole déclaré. | Selon le protocole |

Une commande transactionnelle expose
`{"plan":"preview","apply":"apply"}`. Sans `--apply`, elle retourne
`mode: "plan"` et n'écrit rien. Avec `--apply`, elle revalide les préconditions
puis retourne `mode: "apply"`. `--dry-run` et `--plan` sont refusés : le plan
est déjà le comportement par défaut.

## Entrées

Les erreurs sont rapportées dans l'ordre causal suivant :

1. résolution de la commande ;
2. présence, duplication et appartenance des options ;
3. dépendances et conflits entre options ;
4. nombre et type des opérandes ;
5. type, permissions et lisibilité des fichiers ;
6. syntaxe puis schéma ;
7. politique, état courant et préconditions de concurrence.

Les chemins d'administration sont absolus lorsqu'ils deviennent une
configuration durable. Les secrets doivent être des fichiers réguliers non
symboliques, appartenir au compte agent et n'accorder aucun droit au groupe ou
au monde. Une cible d'écriture existante n'est jamais écrasée implicitement.

## Sorties

`--json` est l'alias exact de `--format json`. `--compact` et
`--pretty=false` sélectionnent une seule ligne sans changer le contrat.
`--non-interactive` garantit qu'aucune question ne sera posée.

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

Codes de processus : `0` pour une commande réussie, `1` pour une erreur
d'exécution, `2` pour une validation correctement exécutée qui a trouvé des
violations. Une décision d'autorisation négative reste une lecture réussie :
l'agent lit `data.allowed`, il ne déduit pas la décision du code de processus.

Codes d'erreur stables actuellement réservés :

| Code | Frontière |
| --- | --- |
| `INVALID_COMMAND` | Commande introuvable. |
| `VALIDATION_FAILED` | Forme d'entrée, option, type ou limite invalide. |
| `PRECONDITION_FAILED` | L'état a changé ou ne permet pas la transaction. |
| `POLICY_FAILED` | Chargement ou évaluation Datalog impossible. |
| `ACCESS_DENIED` | Décision de sécurité négative. |
| `NOT_FOUND` | Ressource requise absente. |
| `IO_FAILED` | Lecture ou écriture système échouée. |
| `PROCESS_FAILED` | Sous-processus Git ou exécuteur échoué. |
| `PROTOCOL_FAILED` | Message ne respectant pas le protocole. |
| `UNSUPPORTED` | Fonction absente de ce build. |
| `UNEXPECTED` | Défaut non classé à corriger dans l'implémentation. |

## Flux protocolaires

Les commandes `stream` sont les seules exceptions à l'enveloppe :

- `maelys-git-shell serve` réserve stdout au smart protocol Git ;
- `maelys-git-hook pre-receive` consomme le protocole de hook Git ;
- `maelys-git-hook post-receive` produit des événements JSONL ;
- `maelys-git-agent stdio` et `maelys-git-executor serve` utilisent
  `maelys-git-agent/1` en JSONL.

Elles refusent les options de rendu JSON. Les diagnostics vont sur stderr et
aucun texte auxiliaire ne peut être injecté dans leur stdout.

## Preuve d'implémentation

Toute modification de commande doit mettre à jour dans le même changement :

1. le catalogue central ;
2. le dispatcher qui consomme l'invocation validée ;
3. le schéma de sortie si sa forme change ;
4. les tests du catalogue, des options et des enveloppes ;
5. la référence générée avec `tools/generate_cli_reference.py`.

Le test de catalogue vérifie notamment l'unicité des identifiants, la présence
des résumés et types, la validité des schémas et la présence de `--apply` pour
chaque transaction.
