# MAELYS-GIT-PREPARED-AUTH-RECEIPTS-v1

Statut : proposée, amendée le 2026-09-05.

État d'implémentation au 2026-09-05 : `matchedPolicy: null` est déjà livré dans
`src/cli/admin.c` et `schemas/authorize.json`. Le constructeur de faits unique,
les sessions préparées confinées à un worker et l'oracle fresh réservé aux
tests sont présents ; CTest couvre le différentiel, A/B/A, la reprise après
erreur et les contextes parallèles. Les révisions consommées sont enregistrées
dans `cmake/dependencies.cmake`. Les reçus, leur sérialisation, leur propagation
et le benchmark restent une proposition, et ne sont pas annoncés comme livrés.
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

### 6.1 Forme

```json
{
  "version": 1,
  "decision": "allow",
  "policySetFingerprint": "<64 hex>",
  "matched": {
    "policyIndex": 0,
    "policyId": "core",
    "policyFingerprint": "<64 hex>"
  },
  "explanation": {
    "kind": "why_true",
    "query": "allow",
    "status": "complete",
    "detailLevel": 0,
    "steps": [
      {"ruleId": 12, "fact": "allow(\"cli\")", "premises": ["user(\"alice\")", "repository(\"team/app\")"]}
    ]
  },
  "stats": {
    "evaluatedPolicies": 1,
    "edbFacts": 17,
    "derivedFacts": 8
  }
}
```

### 6.2 Sémantique des champs

- `decision` est une énumération fermée : `allow`, `deny_explicit`,
  `deny_default`, `deny_error`. Le dernier couvre l'échec fail-closed du
  solveur ; il n'y a pas de reçu partiel, il y a un reçu de refus.
- `matched` vaut `null` pour `deny_default` et `deny_error`. Il ne porte pas de
  `ruleId` : un `deny` peut être dérivé par plusieurs règles, et la règle
  décisive est dans `explanation`.
- `explanation.kind` : `why_true` pour `allow` et `deny_explicit`, `why_false`
  pour `deny_default`, `none` pour `deny_error`. `query` nomme le prédicat
  expliqué.
- `explanation.status` : `complete`, `truncated`, `not_applicable`.
- Pour `why_false`, l'objet porte en plus `limits` (les quatre bornes C69
  utilisées), `limitHits`, `counts` avec `candidateRules`, `substitutions`,
  `diagnostics`, et le tableau `diagnostics`. Ces compteurs sont ceux de
  l'extraction why-false et ne vont pas dans `stats` : sur un `allow` ils
  vaudraient zéro parce que l'extraction n'a pas tourné, pas parce que rien ne
  s'est passé.
- `stats` ne contient que des mesures du solve lui-même : politiques
  évaluées, faits EDB matérialisés, faits dérivés cumulés sur les politiques
  évaluées.
- Toutes les chaînes sont des textes de symboles ou des identifiants de
  politique ; tous les nombres sont des entiers non signés.

### 6.3 Canonicalisation

Le reçu est sérialisé par maelys-json en **Maelys Canonical JSON v1**, profil
`RFC8259` : les principaux, dépôts et chemins ne sont pas garantis ASCII.
Clés triées par unités UTF-16 non échappées, entiers minimaux, un seul épellement
d'échappement, aucun blanc, LF final non demandé.

Les octets canoniques sont la seule forme de référence du reçu. Toute
empreinte du reçu se calcule sur eux, avant insertion dans une enveloppe
Jansson. Une fois insérés puis ré-émis par Jansson, les octets ne sont plus
garantis canoniques ; l'enveloppe porte donc `receiptSha256` calculée sur la forme
canonique, et l'audit SQLite conserve la forme canonique brute.

À réception d'un reçu canonique brut, parser les octets avec les limites du
reçu et valider le schéma, puis exiger que
`maelys_json_document_is_canonical(document, 0, &is_canonical)` retourne
`MAELYS_JSON_OK` avec `is_canonical != 0`. Hacher ensuite les octets d'entrée,
sans les réémettre ; refuser une forme non canonique plutôt que la corriger.
Le transport de ces octets bruts devra être défini avec les reçus : l'objet
de présentation réémis par Jansson ne s'y substitue pas. La forme de
déduplication v1 des commandes reste un contrat Jansson distinct, décrit dans
[Frontières JSON](json-boundaries.md).

Le noyau de politique ne dépend pas de Jansson. Il expose une structure C
`maelys_git_receipt_t` entièrement matérialisée. Un module de sérialisation
séparé, lié à maelys-json, produit les octets canoniques. Ce module est le
seul point de contact du noyau avec un format d'échange.

### 6.4 Budget et troncature déterministe

| Limite | Valeur | Justification |
|---|---|---|
| Octets canoniques | 16 384 | Nettement sous la ligne protocole de 64 Kio, enveloppe comprise. |
| Profondeur | 8 | Le reçu est plat. |
| Nœuds | 2 048 | 16 diagnostics C69 avec supports et substitutions tiennent largement. |

Le writer maelys-json refuse de terminer si une limite est dépassée et ne
produit alors aucun octet. La troncature est une échelle de niveaux de détail
croissants en perte, essayés dans l'ordre jusqu'au premier qui tient :

| `detailLevel` | Contenu |
|---|---|
| 0 | Explication complète. |
| 1 | Sans substitutions ni supports des diagnostics why-false ; sans prémisses des étapes why-true. |
| 2 | Diagnostics ou étapes limités aux quatre premiers dans l'ordre canonique du solveur. |
| 3 | Aucun corps d'explication ; seuls `kind`, `query`, `status`, `detailLevel` et, pour why-false, `limits`, `limitHits`, `counts`. |

Le niveau 3 tient toujours par construction. `status` vaut `truncated` dès que
le niveau retenu est supérieur à 0 ou que C68/C69 a lui-même tronqué. Le
même reçu, sérialisé deux fois, produit les mêmes octets.

## 7. Exposition

### 7.1 `maelys-git authorize`

L'enveloppe normalisée gagne `receipt` (objet) et `receiptSha256`.
`matchedPolicy` est déjà `["integer","null"]` avec `minimum: 0`. Le schéma
`schemas/authorize.json`, son usage dans `src/cli/admin.c` et le contrat généré
`docs/cli-contract.json` sont mis à jour ensemble pour les nouveaux champs ; le
test `maelys-git-cli-docs` les maintient alignés.

### 7.2 Agent

Les résultats `authorize`, `update_ref` et PR portent `receipt` et
`receiptSha256`. Un push évalue une autorisation par ref, commit, fichier et
résumé. Le résultat d'agent porte **le reçu décisif** : le premier refus s'il y
en a un, sinon le reçu de l'autorisation du résumé final. Il porte aussi
`receiptCount`. L'exhaustivité est dans l'audit, pas dans le résultat.

### 7.3 SQLite

La table `audit` existante reçoit un événement par reçu, `kind` =
`authorization_receipt`, `payload` = octets canoniques bruts, sans migration
de schéma. `event_id` est dérivé de l'identifiant de commande et du rang de
l'autorisation.

### 7.4 Hook

Sortie JSONL optionnelle vers un fichier d'audit, un reçu canonique par
ligne, jamais sur stdout. stderr conserve seulement le diagnostic destiné à
Git. Le writer maelys-json remplace l'échappeur maison ; Jansson n'entre pas
dans le hook.

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
