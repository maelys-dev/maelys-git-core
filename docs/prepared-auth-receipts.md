# MAELYS-GIT-PREPARED-AUTH-RECEIPTS-v1

Statut : proposée, amendée le 2026-09-05.

État d'implémentation au 2026-09-05 : `matchedPolicy: null` est déjà livré dans
`src/cli/admin.c` et `schemas/authorize.json`. Le constructeur de faits unique,
les sessions préparées confinées à un worker et l'oracle fresh réservé aux
tests sont présents ; CTest couvre le différentiel, A/B/A, la reprise après
erreur et les contextes parallèles. Les révisions consommées sont enregistrées
dans `cmake/dependencies.cmake`. Les reçus, leur sérialisation et leur
exposition sont livrés par le cycle GIT-C02 : les sections 6 et 7 décrivent le
contrat implémenté.
Les chemins historiques cités plus bas décrivent l'état lors de la rédaction.
Le découpage JSON est désormais fixé module par module dans
[Frontières JSON](json-boundaries.md) : coexistence durable de maelys-json et
Jansson, sans projet de remplacement général.

Cette directive remplace la première ébauche du même nom. Elle intègre les
vérifications faites dans les dépôts réels et fixe la frontière JSON entre
Jansson, maelys-json et le noyau de politique.

## 1. État vérifié des dépendances

| Dépôt | État au 2026-09-02 | Conséquence |
|---|---|---|
| `maelys-git-core` | `main` propre, `51120d1` | Point de départ. |
| `maelys-datalog` | `main` = `origin/main` = `8c8fad1` | C68 (sessions préparées) et C69 (why-false borné) sont publiés et déjà consommés via `../maelys-datalog`. |
| `maelys-json` | `0.1.0` non publié, Makefile seul | Utilisable pour du code neuf après ajout d'un CMake et de tests du writer. |

Actualisation au 2026-09-05 : la cible d'intégration maelys-json est le tag
`v0.1.3`, version `0.1.3`, commit
`0e60ec313388957739968a69c6a78c323b9dd67d`. CMake, la cible `maelys::json`, les
tests et le harnais de fuzz du writer, `writer_value`,
`maelys_json_document_is_canonical` et les drapeaux de présentation sont
présents. Git-core épingle désormais cette révision pour le lecteur de
configuration ; la qualification du writer pour les reçus reste à faire.
Le tableau ci-dessus conserve le constat historique.

L'ébauche précédente considérait C69 comme bloquant parce que non fusionné.
Ce n'est plus vrai. Le seul reste est le qualificatif « Experimental » sur
`maelys_datalog_explain_absent_solved_fact()`, qui est une décision de
qualification à prendre dans maelys-datalog, pas une dépendance.

## 2. Défauts existants corrigés par cette directive

1. **`matchedPolicy: -1`.** L'absence de politique est représentée par
   `SIZE_MAX`, puis castée en entier signé dans `cmd/maelys-git/main.c`. La CLI
   émet donc `-1` alors que `docs/cli-contract.json` exige `minimum: 0`. Le
   nouveau contrat utilise `null`. Ce correctif est livrable seul, avant le
   reste.
2. **CLI et agent divergent.** `decision_result()` dans `src/agent/executor.c`
   n'émet pas la politique appariée. Le reçu unifie les deux surfaces.
3. **Le hook écrit son JSONL à la main.** `maelys_git_post_receive()` enchaîne
   des `fputs` et un échappeur maison. Le writer borné de maelys-json le
   remplace.

## 3. Objectifs

- Faire de chaque `maelys_git_policy_t` un contexte strictement confiné à un
  worker, sans état mutable partagé entre threads.
- Créer une session préparée C68 par ruleset du jeu de politiques au
  chargement, et la conserver pour la durée de vie du contexte.
- Reconstruire une EDB complète à chaque autorisation à partir d'un
  constructeur de faits unique.
- Conserver le chemin fresh actuel comme oracle différentiel de test et de
  benchmark, jamais comme chemin de production.
- Produire, pour chaque autorisation, un reçu déterministe, versionné,
  canonique et borné.

## 4. Hors périmètre

- Évaluation incrémentale et re-saturation.
- Toute modification de l'interaction avec `git cat-file --batch`.
- Migration des lecteurs JSON externes, menée séparément selon la section 10.
  Jansson reste utilisé pour les arbres internes et les enveloppes ; son
  remplacement général est exclu du découpage retenu.
- Signature cryptographique du reçu. Le reçu est conçu pour être signable,
  mais aucune signature n'est produite ici.

## 5. Architecture d'exécution

### 5.1 Contexte de worker

`maelys_git_policy_t` devient le contexte d'un worker. Il contient :

- le jeu de politiques chargé et son empreinte, déjà calculée par
  `maelys_datalog_policy_set_fingerprint()` ;
- une session préparée par politique, dans l'ordre du jeu, jusqu'à la capacité
  de `maelys_datalog_policy_set_t` ;
- le tampon de reçu du dernier solve.

Les confinements naturels existants suffisent : un processus séquentiel par
push pour le hook, une boucle séquentielle pour l'agent `stdio`, un exécuteur
isolé par commande pour l'agent Cloud. Aucun verrou n'est ajouté. Un contexte
ne doit jamais être partagé entre threads ; cette règle est documentée dans
`include/maelys_git.h`.

### 5.2 Constructeur de faits unique

Le chemin prepared reçoit des `maelys_datalog_input_fact_t` à symboles
textuels, alors que le chemin fresh appelle directement l'EDB. Pour éviter la
divergence, un seul constructeur produit une liste intermédiaire de faits
d'entrée à partir de `maelys_git_policy_request_t`. Le chemin prepared la
passe à `maelys_datalog_prepared_session_solve_ex()`. Le chemin fresh la
consomme pour alimenter son EDB. Les helpers `add_*_fact` actuels de
`src/policy/policy.c` deviennent l'implémentation de ce constructeur et ne
sont plus appelés ailleurs.

### 5.3 Évaluation

Pour chaque politique dans l'ordre du jeu :

1. solve prepared avec la liste de faits ;
2. interrogation de `deny(request)` puis `allow(request)` ;
3. arrêt au premier `deny` explicite.

La sémantique de décision est inchangée : deny explicite prioritaire, premier
allow retenu, refus par défaut sinon, échec fail-closed sur toute erreur du
solveur.

### 5.4 Cycle de vie du résultat

Une session n'autorise qu'un résultat vivant à la fois et refuse d'être
détruite tant qu'il existe. Les textes de symboles renvoyés par la session ne
sont valides que jusqu'au solve suivant, car les symboles runtime sont
réinitialisés à chaque solve. Le reçu est donc **entièrement matérialisé**,
textes copiés dans des tampons bornés, avant `maelys_datalog_solve_result_free()`
et avant le solve de la politique suivante.

### 5.5 Chemin fresh comme oracle

`solve_policy()` actuel est conservé comme fonction interne non exportée. Les
tests l'exécutent en parallèle du chemin prepared et exigent l'égalité stricte
de la décision et du reçu, champs de statistiques inclus. Le benchmark
l'utilise comme référence de coût.

## 6. Reçu d'autorisation

Livré par le cycle GIT-C02 (directive R5) : cette section décrit le contrat
implémenté, qui remplace la proposition du 2026-09-05. Le reçu ne recopie
plus le corps de la preuve : il en garde un résumé borné, lu dans les vues
structurées du moteur, et l'empreinte du document, qui voyage à côté.

### 6.1 Forme, version 1

```json
{
  "decision": "deny_explicit",
  "errorBudget": null,
  "errorCode": null,
  "errorKind": null,
  "explanation": {
    "counts": null,
    "kind": "why_true",
    "limitHits": null,
    "policyIndex": 0,
    "premiseCount": 6,
    "query": "deny",
    "ruleId": 12,
    "status": "complete",
    "stepCount": 1,
    "textBytes": 609,
    "textSha256": "<64 hex>"
  },
  "matched": {"policyId": "maelys-git.example.authorization", "policyIndex": 0,
              "sessionFingerprint": "<64 hex>"},
  "policySetFingerprint": "<64 hex>",
  "request": {"id": "cli", "operation": "push", "pathCount": 0, "principal": "mallory",
              "ref": "refs/heads/main", "repository": "example.git"},
  "stats": {"edbFacts": 8, "evaluatedPolicies": 1},
  "version": 1
}
```

### 6.2 Sémantique des champs

- `decision` : `allow`, `deny_explicit`, `deny_default`, `deny_error`.
  `deny_error` est l'échec d'une autorisation : `errorCode` est le nom du code
  de résultat, `errorKind` le genre d'échec de GIT-C04 (`capacity`,
  `syntax`, `semantics`, `manifest`, `value`, `engine`) et `errorBudget` le
  nom du budget du moteur pour une capacité. Ces trois champs valent `null`
  hors `deny_error`. La valeur demandée et la limite n'y sont pas : elles
  dépendent du profil du moteur.
- `matched` vaut `null` pour `deny_default` et `deny_error`.
- `explanation.kind` vaut `none` et `status` `not_requested` quand aucune
  explication n'a été demandée ; tous les autres champs valent alors `null`.
  `why_true` explique `allow` ou `deny` dans la policy décisive ;
  `why_false` explique `allow` dans la dernière policy du jeu.
- `status` vient de la vue structurée, jamais du texte : `complete`,
  `truncated`, `not_applicable`, ou `unknown` quand le backend n'offre pas de
  vue.
- `ruleId`, `stepCount` et `premiseCount` ne valent que pour un Why-true
  `complete` ; `ruleId` est l'index de la règle dans le programme compilé,
  plus un, et n'a de sens que pour `matched.sessionFingerprint`. `counts` et
  `limitHits` ne valent que pour un Why-false.
- `textBytes` et `textSha256` désignent le document `MAELYS-DATALOG-v2`
  rendu ; le document n'est jamais dans le reçu.
- `request` ne contient pas les chemins, seulement leur nombre. `stats`
  compte les faits de requête construits et les policies résolues.
- Tous les nombres sont des entiers non signés.

### 6.2 bis Version 2 : les droits utilisés (GIT-C06)

Une décision prise avec un instantané de droits porte le membre `grants`, et
`version` vaut 2. C'est le cas quand une policy du jeu lit les prédicats
`slice_*` ; seul le programme Gitolite audité en a le droit. Tous les autres
membres sont ceux de la version 1.

```json
"grants": {
  "facts": 2,
  "format": "maelys-git-grants/1",
  "program": "maelys-git-gitolite-program/1",
  "sha256": "<64 hex>",
  "slice": "maelys-git-slice/1"
}
```

- `sha256` est l'empreinte des octets de l'instantané lu à l'ouverture.
- `facts` compte les tuples distincts de la tranche donnés au moteur pour
  cette requête, tous prédicats `slice_*` confondus. Il vaut 0 quand la
  tranche est refusée avant d'être donnée, par exemple pour une capacité.
- `stats.edbFacts` compte les faits de la requête seuls, ceux que reçoit
  chaque policy du jeu. La tranche n'est donnée qu'au programme audité.
- `format`, `slice` et `program` sont fixés par la version 2.

Sans instantané, le reçu reste en version 1, octet pour octet. Le lecteur
accepte les deux versions : `grants` en version 2, et seulement là.

### 6.3 Canonicalisation et vérification

Le reçu est écrit par maelys-json en Maelys Canonical JSON v1, profil
`RFC8259`, sans saut de ligne final ; son empreinte est le SHA-256 de ces
octets. `maelys_git_receipt_verify` n'accepte que cette forme, les clés
fermées de la version 1 ou de la version 2, les énumérations, les formats
fixés de `grants` et les longueurs d'empreinte, et
refuse fraction et exposant. Un reçu relu dans une enveloppe est réécrit par
maelys-json puis vérifié avant d'être haché : depuis maelys-json 0.3.0, la
réécriture recopie un nombre non entier par son lexème, et ne prouve donc
rien seule.

### 6.4 Budget

Un reçu fait au plus 8 192 octets canoniques ; tous ses champs sont bornés
par des limites du produit, et le plus grand reçu possible, champs au
maximum et `grants` compris, tient en 3 621 octets. Un document d'explication est exposé jusqu'à
32 768 octets ; au-delà il ne l'est pas, et le reçu garde sa taille et son
empreinte.

## 7. Exposition

| Surface | Explication rendue | Texte exposé |
|---|---|---|
| `maelys-git authorize` | jamais | non |
| `maelys-git authorize --explain` | toujours | `explanationText` |
| Agent, `authorize` | jamais | non |
| Agent, `authorize` avec `explain: true` | toujours | `explanation_text` |
| Exécuteur supervisé, refus de `create_repository` ou `update_ref`, refus de policy de `pr_merge` | sur refus | vers l'agent superviseur |
| Résultat publié par l'agent Cloud pour ce refus | — | non : retiré après audit |
| Audit SQLite, `authorization_receipt` | — | le reçu canonique seul |
| Audit SQLite, `authorization_explanation` | — | le texte d'un refus ou d'une demande |
| Audit SQLite, `grants_snapshot` | — | l'empreinte et le chemin, dans le magasin de l'agent, de l'instantané des droits donné à l'exécuteur ; jamais ses octets |
| Audit SQLite, `grants_store_pruned` | — | les empreintes qu'une purge du magasin a retirées, et le chemin du magasin |
| Hook avec `--receipts FILE`, refus | sur refus | dans le fichier |
| Hook avec `--receipts FILE`, acceptation | jamais | non |
| `maelys-git-agent stdio`, refus de `create_repository` ou `update_ref`, refus de policy de `pr_merge` | jamais | non ; le reçu n'a pas de résumé (`explanation.kind` vaut `none`) |
| Refus de `pr_merge` par ses gates ou sa fusionnabilité | — | aucun reçu (voir plus bas) |
| Client Git | — | jamais |

- `maelys-git authorize` ajoute `receipt` et `receiptSha256` à ses quatre
  membres, inchangés.
- Les résultats de décision de l'agent ajoutent `matched_policy`, `receipt`
  et `receipt_sha256`.
- L'agent Cloud vérifie le reçu et le texte d'un résultat avant de
  l'enregistrer ; les deux événements d'audit, l'enregistrement du résultat
  et sa mise en file sont dans la même transaction.
- Le hook écrit une ligne par push, `{"explanationText":…,"receipt":{…},
  "receiptSha256":"…"}`, par maelys-json ; le flux vers le client Git est le
  même avec ou sans l'option.
- `maelys-git-agent stdio` publie ce que l'agent Cloud publierait, sans
  l'audit qui seul justifie de rendre le texte d'un refus : il n'explique
  donc pas le refus d'une commande qui modifie un dépôt.
- `pr_merge` est réautorisé par `mg_pr_merge`, qui rend comme
  `mg_receive_authorize` la dernière décision et le reçu décisif : le premier
  refus, en plan comme en apply. Un refus qui n'est pas celui de la policy
  (gates de PR, PR vide ou non fusionnable) garde sa charge `{code, message}`
  et ne porte pas de reçu : aucune décision ne l'a rendu.

### Corpus de référence

`tests/fixtures/receipts/receipts.tsv` est le contrat d'octets de la version
1 : trente reçus, comparés à l'octet près dans les profils SMALL et LARGE. Il
est régénéré par `MG_RECORD_RECEIPTS=FICHIER` uniquement dans un commit qui
explique chaque ligne changée ; une montée du moteur qui change une empreinte
le régénère dans son propre commit, jamais dans celui d'une fonctionnalité.

## 8. Préalables

### 8.1 maelys-datalog

1. Ajouter l'accès inverse aux symboles de la session préparée :

   ```c
   const char *maelys_datalog_prepared_session_symbol_text(
       const maelys_datalog_prepared_session_t *session,
       maelys_datalog_symbol_id_t id);
   ```

   C'est un wrapper de `maelys_datalog_symbol_text()` sur la table de la
   transaction courante. Le pointeur est valide jusqu'au solve suivant.
2. Décider du statut de `maelys_datalog_explain_absent_solved_fact()` :
   retirer « Experimental » ou documenter que git-core en dépend en l'état.
3. Épingler le commit consommé dans le CMake de git-core.

### 8.2 maelys-json

1. Épinglage déjà réalisé pour le lecteur de configuration : cible CMake
   `maelys::json`, tag
   `v0.1.3` : version `0.1.3` et commit résolu
   `0e60ec313388957739968a69c6a78c323b9dd67d` dans
   `cmake/dependencies.cmake`.
2. Qualifier les tests existants du writer sur la révision retenue : tri
   UTF-16 et préfixes partagés, dépassement d'octets, de profondeur et de
   nœuds, clés dupliquées à l'écriture.
3. Exécuter le harnais de fuzz existant et compléter si nécessaire le corpus
   d'aller-retour pour les reçus. La présence du harnais n'est pas une preuve
   de qualification de l'intégration.

### 8.3 maelys-git-core

1. Préserver le correctif déjà livré `matchedPolicy: null`, schéma et contrat
   inclus.
2. Préserver l'absence de Jansson dans les cibles CLI communes au shell et au
   hook. La sérialisation des reçus utilise maelys-json et ne doit pas
   introduire Jansson dans `src/hooks/pre_receive.c`.

## 9. Validation

- **Différentiel fresh contre prepared** sur tout le corpus de tests de
  politique : décision et reçu identiques, octets canoniques identiques.
- **Séquences A/B/A** : trois requêtes distinctes sur la même session, le reçu
  de la troisième est identique à celui de la première, preuve du reset
  intégral de l'EDB et des symboles runtime.
- **Workers parallèles** : plusieurs contextes dans des threads distincts,
  chacun avec ses sessions, sous ASan et TSan, reçus identiques à l'exécution
  séquentielle.
- **Cas de décision** : allow, deny explicite, deny par défaut, deny d'erreur
  fail-closed, why-false tronqué par chacune des quatre bornes.
- **Troncature** : un reçu forcé au-delà de 16 Kio descend l'échelle jusqu'au
  premier niveau qui tient, et jamais au-delà ; deux sérialisations donnent
  les mêmes octets ; aucun octet n'est produit en cas d'échec.
- **Surfaces** : la CLI, l'agent `stdio`, l'agent Cloud et le hook produisent
  le même reçu canonique pour la même requête.
- **Pushes** : petit, moyen, et refus en cours de transaction ; le reçu
  décisif est le bon et `receiptCount` correspond au nombre d'autorisations.
- **Benchmark** : temps total, coût par autorisation, faits dérivés, fresh
  contre prepared, rapporté hors CTest. Aucun seuil temporel dans CTest.

## 10. Frontière JSON et coexistence

Le découpage normatif et l'inventaire du code sont dans
[Frontières JSON : maelys-json et Jansson](json-boundaries.md). Ils remplacent
le projet antérieur de migration complète : les deux bibliothèques répondent
à des modèles différents.

maelys-json prend en charge les lectures JSON aux frontières de confiance
(configuration, requêtes, lots Cloud, réponses de l'exécuteur, manifestes en
coordination avec maelys-datalog) et les octets JSON hachés ou signés. Jansson
reste pour les constructions de réponses et d'enveloppes et les arbres
internes mutables. Le choix se fait par opération : migrer le lecteur de
configuration n'impose pas de réécrire son writer.

Le chantier des reçus introduit son writer dédié. Les migrations des lecteurs
restent des livraisons séparées avec limites explicites, validation typée,
durée de vie des documents et compatibilité du journal d'idempotence. Le
préparse actuel des manifestes utilise yyjson puis le chargeur maelys-datalog
rouvre le fichier : sécuriser seulement le préparse ne traite pas toute cette
frontière.

`include/maelys_git_cli.h` n'expose déjà plus `json_t`. Les constructeurs
Jansson internes et leur dépendance CMake sont conservés. Ni leur nombre ni
la disponibilité de nouveaux helpers maelys-json ne justifient une migration
générale.

## 11. Ordre de livraison

1. Correctif `matchedPolicy` et contrat CLI.
2. Préalables maelys-datalog et maelys-json.
3. Constructeur de faits unique, chemin fresh isolé en oracle.
4. Sessions préparées et contexte de worker, différentiel vert.
5. Structure de reçu et sérialisation canonique, troncature.
6. Exposition CLI, agent, SQLite, hook.
7. Benchmark et documentation.
