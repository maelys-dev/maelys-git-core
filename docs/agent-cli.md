# Utiliser les CLI Maelys depuis un agent

## Séquence minimale

```sh
maelys-git describe --summary --format json --compact --non-interactive
maelys-git describe repo.init --format json --compact --non-interactive
maelys-git repo init /srv/git example.git --format json --compact --non-interactive
# Examiner data.precondition et les autres champs du plan.
maelys-git repo init /srv/git example.git --apply --format json --compact --non-interactive
```

Ne construisez pas une commande depuis le texte de `help`. Utilisez
`data.commands[].input`, puis lisez uniquement l'enveloppe de stdout. En cas de
code `1`, stdout doit être vide : analysez l'enveloppe de stderr et suivez
`error.hint`. En cas de code `2`, l'appel lui-même a réussi et `data.valid`
vaut faux.

## Principes pour l'automatisation

- identifiez une commande avec `command`, jamais avec son libellé humain ;
- vérifiez `contract == "agent-cli/v2"` et `schemaVersion == 2` ;
- considérez `data` comme régi par `outputSchema` du descripteur installé ;
- n'ajoutez `--apply` qu'après avoir relu le plan de la même commande ;
- recopiez les préconditions du plan quand une option dédiée existe ;
- ne rejouez pas aveuglément une erreur `PRECONDITION_FAILED` ; relisez l'état ;
- n'utilisez aucune option de rendu sur une commande `outputMode` de flux ;
- ne mélangez jamais stdout et stderr.

Les sorties compactes économisent des tokens sans modifier le schéma :

```sh
maelys-git authorize policies/manifest.json alice example.git read \
  --format json --compact --non-interactive
```

Une autorisation refusée produit `exitCode: 0`, `ok: true` et
`data.allowed: false`. Toute décision porte `data.receipt`, son reçu en Maelys
Canonical JSON v1, et `data.receiptSha256`, l'empreinte de ses octets
canoniques : relisez le reçu par un lecteur conforme, réécrivez-le en forme
canonique, et l'empreinte de ces octets est celle-là. `--explain`, écrit
avant `--`, ajoute le document d'explication du moteur dans
`data.explanationText` ; après `--`, c'est un chemin comme un autre. Une politique impossible à charger produit une erreur
stable. `validate` produit plutôt un rapport réussi avec le code de processus
`2` lorsqu'il peut établir que le manifeste est invalide.

## Inventaires disponibles

Chaque binaire possède son propre catalogue, produit par `libmaelys_cli`
(`data.framework` en donne la version) :

```sh
maelys-git describe --summary --format json
maelys-git-agent describe --summary --format json
maelys-git-executor describe --summary --format json
maelys-git-shell describe --summary --format json
maelys-git-hook describe --summary --format json
```

La référence Markdown et le catalogue agrégé sont générés à partir de ces cinq
réponses, jamais maintenus comme une seconde définition manuelle. Une commande
dont `outputMode` vaut `protocol-stream` déclare son `protocol` ; ne lui passez
aucune option de rendu.
