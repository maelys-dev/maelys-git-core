# Matrice concurrentielle : Maelys Git Core, Gitolite et Forgejo

Etat verifie le 17 octobre 2026. La comparaison porte sur le code present
et teste dans ce depot. Elle ne credite pas a Maelys Git Core les fonctions
prevues pour une future forge Cloudflare.

## Legende

- **Complet** : fonction utilisable dans son perimetre annonce.
- **Partiel** : primitive presente, mais workflow, compatibilite ou produit
  incomplet.
- **Absent** : fonction non implementee.
- **Extensible** : realisable par extension ou hook, sans constituer une
  fonction integree equivalente.

Les trois projets n'ont pas le meme perimetre : Gitolite est d'abord une
couche d'autorisation devant Git, Forgejo est une forge complete, et Maelys
Git Core vise un noyau local de securite pilotable par une forge separee.

## Matrice

| Domaine | Capacite | Maelys Git Core | Gitolite | Forgejo | Priorite Maelys |
|---|---|---|---|---|---|
| Transport | Confinement SSH sans shell utilisateur | **Complet** : analyse stricte, confinement du depot, `execve`/`posix_spawn` | **Complet** : compte Unix unique et commandes forcees | **Complet** : serveur SSH integre ou OpenSSH | Acquis |
| Transport | Git smart HTTP/HTTPS | **Absent** : l'HTTPS actuel transporte les commandes de l'agent, pas Git | **Partiel** : smart HTTP pris en charge, moins central que SSH | **Complet** | P1 si une forge Web l'exige |
| Autorisation | Lecture, ecriture et creation par depot | **Complet** : decisions Datalog et creation bare dynamique | **Complet** | **Complet** | Acquis |
| Autorisation | Groupes d'utilisateurs | **Complet** dans les politiques et groupes imbriques dans la migration ; includes/LDAP externes | **Complet** : groupes, inclusions, macros, LDAP extensible | **Complet** : utilisateurs, organisations et equipes | P1 pour les sources dynamiques |
| Autorisation | Regles par branche, tag et type de mise a jour | **Complet** dans le noyau ; migration des full refs exactes, des prefixes litteraux et des refex regex en droits comme donnees ; refus prioritaire au lieu de la premiere regle | **Complet** : refex, creation, suppression, rewind et ordre des regles | **Complet** : protections de branches et tags, glob/regex selon le type | P2 : ordre des regles |
| Autorisation | Regles selon les fichiers modifies | **Complet** : tous les changements sont streams, sans plafond historique de 64 chemins | **Complet** : `VREF/NAME` | **Partiel** : protections de refs, sans moteur general de faits par chemin equivalent | Avantage Maelys |
| Autorisation | Renommages et double chemin ancien/nouveau | **Complet** : `path` et `old_path` | **Partiel** : le VREF expose les noms touches, sans domaine type de renommage equivalent | **Partiel** : pas de domaine de politique general equivalent | Avantage Maelys |
| Autorisation | Faits sur objets Git | **Complet** : taille, mode, binaire, symlink, submodule et pointeur LFS | **Partiel** : VREF livres pour compte, nom, type et taille de nouveaux binaires ; extensions possibles | **Partiel** : controles integres cibles, sans faits composables equivalents | Avantage Maelys |
| Autorisation | Identite et signature des commits | **Complet** : email, etat, empreinte, identite et confiance injectes en Datalog | **Partiel/extensible** : `EMAIL-CHECK` livre et VREF personnalises | **Complet** : verification et politiques de signature integrees | Acquis |
| Autorisation | Quotas dans le temps (par heure, par jour) | **Absent** : aucune memoire d'un push a l'autre ; mecanisme cadre, compteur declare par la politique et reserve atomiquement | **Extensible** : VREF personnalise | Non verifie | P2 : apres le recu de decision |
| Autorisation | Quotas sur une transaction multi-ref | **Complet** : commits, chemins, octets et inspection cumules sur tout le receive | **Partiel** : `COUNT` et autres VREF sont principalement evalues par mise a jour de ref | **Partiel** : quotas et limites integres, sans domaine Datalog transactionnel equivalent | Avantage Maelys |
| Autorisation | Extension de la politique | **Complet** : regles Datalog versionnees et inspecteurs C bornes | **Complet** : vaste ecosysteme VREF, triggers et commandes | **Partiel** : hooks et code de la forge, moins adaptes aux politiques locales declaratives | P1 : bibliotheque de politiques |
| Audit | Explication et preuve d'une decision | **Partiel** : explications Why-true et Why-false du moteur, empreinte du jeu de politiques et de la session ; recu compact versionne specifie (cycle GIT-C02), non implemente | **Partiel** : test et diagnostic de regles, sans preuve declarative equivalente | **Partiel** : motifs fonctionnels et journaux, sans preuve de politique equivalente | P1 : decision receipt |
| Cles | Cles utilisateur et deploy keys | **Complet** : compilation atomique, validation, portee depot, lecture seule, expiration et revocation | **Complet** pour les cles utilisateur ; deploy keys specialisees a construire par convention/extension | **Complet** | P1 : rotation et attestation |
| Depots | Creation dynamique | **Partiel avance** : segments/depth/leaf injectes en Datalog et migration de `NAMESPACE/CREATOR/..*`; pas de moteur regex general | **Complet** : wild repos, regex, `CREATOR` et permissions dynamiques | **Complet** : UI/API et push-to-create configurable | P1 : autres patrons choisis |
| Depots | Inventaire, inspection, renommage, archive, suppression recuperable et restauration | **Complet** : plan/apply et preconditions CAS | **Partiel** : administration centree configuration ; operations de cycle de vie souvent externes | **Complet** via la forge, avec modele plus riche | Acquis pour le local |
| Depots | Mirroring | **Partiel avance** : miroir local idempotent, refs atomiques, HEAD et preconditions ; pas de redirection/scheduling distribue | **Complet** : maitres/copies, synchronisation et redirection avec limites documentees | **Complet** : miroirs de depot | P1 : orchestration distante |
| Administration | Delegation d'administration | **Partiel** : faits `delegate_namespace` bornes au namespace ; pas encore de publication transactionnelle de sous-politiques | **Complet** : `subconf` et `VREF/NAME` | **Complet** : organisations, equipes et permissions | P1 |
| Migration | Import de configuration Gitolite | **Partiel avance** : groupes imbriques, depots exacts, `C/R/RW/RW+`, wild `CREATOR`, full refs exactes, prefixes litteraux et refex regex, VREF `NAME/COUNT/MAX_NEWBIN_SIZE`; refus ferme du reste | Sans objet | Sans objet | P1 : includes et subconf |
| API | CLI normalise et decouvrable par un agent | **Complet** : enveloppe `agent-cli/v2`, catalogues JSON et plan/apply | **Partiel** : CLI et commandes SSH scriptables, sans contrat homogene equivalent | **Complet** : CLI, API HTTP et interface Web | Avantage Maelys pour l'automatisation locale |
| API | Agent distant durable | **Complet** dans son perimetre : HTTPS long-poll, journal SQLite, idempotence et outbox | **Absent** comme protocole integre | **Complet** autrement via API, webhooks et services de la forge | P1 : annulation et observabilite |
| Pull requests | Analyse de conflit et preparation FF/merge/squash | **Complet** dans un meme depot ou entre forks, deterministe et sans mutation du depot cible pendant le plan | **Absent** | **Complet** | Acquis pour le noyau PR |
| Pull requests | Application atomique et reautorisee | **Complet** : CAS, empreinte de politique et transaction refs target/head/resultat | **Absent** | **Complet** dans le workflow de la forge | Avantage de surete a conserver |
| Pull requests | Approbations et checks obligatoires | **Partiel** : gates fournis par la forge et verifies localement, sans stockage durable | **Absent** | **Complet** | P0 : modele durable cote forge |
| Pull requests | PR entre forks et quarantaine d'objets | **Complet pour le noyau local** : source/ref exacts, quotas, `fsck`, identite/OID revus et promotion sans ref de quarantaine visible | **Absent** | **Complet** | Acquis ; etat durable cote forge restant |
| Collaboration | PR persistantes, revues, commentaires et historique | **Absent** | **Absent** | **Complet** | P0 cote forge : objectif annonce le 15 octobre 2026 |
| Collaboration | Issues, labels, projets et wiki | **Absent** | **Absent** | **Complet** | P2 cote forge |
| Distribution | Releases et stockage d'objets Git LFS | **Absent** : detection des pointeurs LFS seulement | **Absent** comme services integres | **Complet** | P2 |
| Integration | Webhooks et notifications | **Partiel** : evenements normalises, `post-receive` et outbox ; pas d'abonnements ni de livraison Web publique | **Extensible** : triggers/hooks, pas un produit webhook integre | **Complet** | P1 |
| Forge | Navigation Web, recherche et blame | **Absent** | **Absent** | **Complet** | P2 |
| Forge | Comptes Web, tokens, OAuth/OIDC/LDAP et SSO | **Absent** : identite SSH locale et bearer token d'agent seulement | **Partiel/extensible** : SSH principal, smart HTTP et LDAP pour groupes | **Complet** | P1 cote forge |
| Forge | CI integree | **Absent** | **Absent** | **Complet** : Forgejo Actions et runners separes | P1 : objectif annonce le 15 octobre 2026, service separe |
| Forge | Registry de paquets | **Absent** | **Absent** | **Complet** | P3 |

## Lecture strategique

### Face a Gitolite

Maelys Git Core a deja depasse le modele ACL classique sur les points ou son
architecture Datalog apporte une vraie difference : composition de faits,
renommages, inspection d'objets, quotas globaux au receive et preconditions de
politique. Il couvre maintenant le socle des groupes imbriques, refs exactes,
wild repos avec `CREATOR`, VREF usuels et miroirs locaux. Gitolite reste devant
pour l'ordre des regles, `subconf`, la delegation publiee, la redirection de
miroirs et l'ecosysteme d'extensions historiques.

### Refex migrees

Gitolite ancre un refex au debut et non a la fin, complete par `refs/heads/`
un nom qui ne commence pas par `refs/`, et lit un `$` final comme une egalite.
La migration lit un refex dans cet ordre :

1. un refex qui nomme `/USER/` une fois complete est refuse : Gitolite y met
   le nom de chaque utilisateur ;
2. un refex fait de `[A-Za-z0-9_/-]` et des echappements `\.`, `\/` et `\-`
   est un nom litteral, migre en egalite ou en prefixe quand l'equivalence
   est exacte ;
3. tout autre refex est une regex : complete, garde tel qu'ecrit et ancre au
   debut, il devient un motif de forme `regex` de l'instantane
   `maelys-git-grants/2`, lu avec le sous-ensemble de `maelys/cli/regex.h`
   (maelys-cli 0.13.0). Les restrictions sont celles du lecteur d'un
   instantane (`mg_refex_regex_check`) : au plus 256 octets complete
   compris, pas de `|` au niveau superieur, pas de `^` hors d'une classe,
   au plus 4 096 etats. Un refus donne la colonne du refex tel qu'ecrit ou
   la lecture s'est arretee : sa derniere colonne pour une limite que seule
   la fin revele (`(a{255}){17}` : colonne 12), le premier octet au-dela
   de la borne pour un refex de plus de 256 octets une fois complete. Un
   echappement hors du sous-ensemble est signale sur le caractere echappe :
   `a\d` en colonne 3, `refs/heads/a\d` en colonne 14.

L'instantane n'est `/2` que s'il contient un motif regex ; sinon il reste
`/1`, octet pour octet. Le plan le dit dans `grantsFormat`. Une regex n'est
migree qu'en droits comme donnees : la politique compilee la refuse
(`a regex refex is migrated as grants as data only`).

| Forme Gitolite | Resultat | Remarque |
| --- | --- | --- |
| `RW refs/heads/release/ = alice` | fait `gitolite_ref_access("alice", P, "refs/heads/release/", "RW")`, lu par `ref_prefix` | prefixe d'espace de noms |
| `RW topic/ = alice` | fait sur `refs/heads/topic/` | nom court complete |
| `RW refs/heads/stable$ = alice` | fait exact sur `refs/heads/stable` | egalite |
| `RW refs/heads/main = alice` | fait exact sur `refs/heads/main` | plus strict que Gitolite, qui y lit un prefixe |
| `- refs/heads/main = mallory` | regle `starts_with(F, "refs/heads/main")` | comme Gitolite ; refuse aussi `main-hotfix` |
| `RW refs/tags/v1\.0$ = alice` | fait exact sur `refs/tags/v1.0` | point litteral |
| `- refs/tags/v1\. = mallory` | regle `starts_with(F, "refs/tags/v1.")` | comme Gitolite |
| `RW+ personal/USER/ = @all`, `- USER/ = mallory`, `- VREF/NAME/USER/x = mallory` | refuse, `'/USER/' is the user's own name in Gitolite` | Gitolite y met le nom de chaque utilisateur, une fois le refex complete |
| `RW refs/heads/feature/.* = alice`, `RW v[0-9]+ = alice` | motif `regex` `refs/heads/feature/.*`, `refs/heads/v[0-9]+` | comme Gitolite |
| `- refs/tags/v1.0 = mallory`, `RW refs/tags/v1.0$ = alice` | motif `regex` | comme Gitolite : `.` est un caractere quelconque, `v1x0` compris |
| `RW refs/heads/(main\|dev) = alice` | motif `regex` | alternance dans un groupe |
| `RW main\|dev = alice` | refuse, `refex refused at column 5: a '\|' at the top level` | Gitolite y lit `^main` ou `dev` n'importe ou |
| `RW ^main = alice`, `RW refs/heads/a\d = alice` | refuse, `refex refused at column N: ...` | ancre deja posee ; echappement hors du sous-ensemble |
| prefixe de plus de 63 octets ou de plus de 16 `/` | regle `starts_with` | hors des faits `ref_prefix` |
| motif de plus de 256 octets | refuse, `ref pattern exceeds 256 bytes`, avec la colonne pour une regex | borne du moteur |

Une regex garde la lecture de Gitolite, ancree au debut seulement : en
attribution, `RW refs/heads/release[0-9] = alice` autorise aussi
`release1-x`, la ou le litteral nu `RW refs/heads/release = alice` reste une
egalite (plus strict) ; en refus, `- refs/tags/v[0-9] = mallory` refuse aussi
`v1x`, comme le refus litteral nu.

Gitolite lit ces formes en Perl ; elles sont hors du sous-ensemble de
`maelys/cli/regex.h` et refusees, jamais approchees. La colonne est celle du
refex ecrit apres `RW ` :

| Refex | Refus |
| --- | --- |
| `a{` | colonne 2 : `a bound that is not {m}, {m,} or {m,n} in decimal` |
| `a{x}` | colonne 4 : idem |
| `[]a]` | colonne 2 : `a bracket expression outside the subset` |
| `[a-z-9]` | colonne 5 : idem |
| `a{1,256}` | colonne 8 : `a bound above 255, more than 32 nested groups or more than 65536 states` |
| `a*?`, `a++` | colonne 3 : `a quantifier outside the subset` |
| `a\d`, `a\w` | colonne 3 : `an escape that is not of a metacharacter` |
| `(?:a)` | colonne 2 : `a group, a ')', a ']' or a '}' outside the subset` |

Une regex de l'instantane est compilee une fois, a sa lecture, dans les
budgets de D3 : 4 096 etats par motif, 4 096 pour les motifs distincts d'un
depot, 1 048 576 pour l'instantane. Elle est cherchee sans allocation, une
fois par ref et par motif : les requetes d'un push qui portent une meme ref
ne la cherchent pas de nouveau.

Le plan rend aussi `remarks`, qui ne bloquent jamais la migration : un depot
qui porte a la fois des droits d'ecriture et des refus de refs, ou tout
refus qui s'applique l'emporte quel que soit son ordre chez Gitolite (plus
strict), et un groupe qui porte des droits sans aucun membre. Une remarque
dit que l'ordre pourrait changer une decision, pas qu'il la change.

Un prefixe de tag de version comme `refs/tags/v` n'est donc pas migre en
autorisation : ecrit nu, il reste une egalite. Il s'ecrit a la main,
`starts_with(F, "refs/tags/v")`, dans une politique Datalog. `ends_with` et
`contains` ne sont jamais produits par la migration : Gitolite n'ancre pas la
fin et une sous-chaine libre suppose `.*`.

Une attribution elementaire, sujet, depot ou espace de noms, ref ou prefixe,
niveau, coute un fait de politique et aucune regle, sauf le refus d'un
litteral nu et les prefixes hors des faits `ref_prefix`, qui coutent une
regle. Le socle d'autorisation genere compte 67 regles sur 128 et ne lit les
faits de politique qu'apres avoir lie le sujet, le depot et la ref de la
requete : ce qu'un predicat derive contient depend de la requete, jamais de
la taille de la configuration. Mesure en SMALL et en LARGE : 128 lignes `RW`
sur un depot (128 faits), 120 prefixes `RW+` de sujets distincts (borne des
256 atomes de politique), 61 refus nus (borne des regles). Un prefixe en fait
coute un fait et un atome ; quand ces budgets refusent la politique, la
migration la regenere avec ses prefixes en regles et la garde si elle tient :
une configuration admise par la forme en regles reste admise.

### `@all`

Comme Gitolite, `@all` est le groupe de tout utilisateur, connu de la
configuration ou non : `RW+ = @all` (la configuration par defaut de
Gitolite) donne l'acces a chacun, et un refus `- refs/heads/x/ = @all`
s'applique a chacun. Le groupe `all` est reserve : `@g = @all` et
`@all = ...`, sans effet chez Gitolite, sont refuses a la migration, et un
instantane qui donne un membre a `all` ou l'imbrique est refuse a la
lecture. Chez Git Core, "chacun" est tout principal authentifie : il
n'y a pas d'acces anonyme `daemon` ou `gitweb`. `all` compte parmi les
groupes d'un utilisateur : 63 groupes directs au plus, 64 avec lui.

### Refs admises

Gitolite 3.6.15, avec ses motifs d'admission par defaut
(`REF_OR_FILENAME_PATT` de `Rc.pm`), refuse une ref hors de son alphabet
avant toute regle. Git Core fait de meme pour tout ensemble de politiques
qui contient le programme Gitolite audite, reconnu a son empreinte : une
ref invalide, qui ne commence pas par une lettre ou un chiffre, qui contient
autre chose que `[-0-9A-Za-z._@/+,]` ou qui depasse 511 octets est une requete
invalide (`invalid_argument`), refusee avant toute evaluation, meme si une
politique ecrite a la main de l'ensemble l'autoriserait ; aucun recu de
decision n'est produit. Une requete sans ref et les chemins de fichiers ne
sont pas concernes. Un ensemble ecrit a la main seul garde son
comportement. Une configuration qui redefinit ces motifs dans
`.gitolite.rc` est hors du perimetre de fidelite garanti. Une ancienne
politique compilee (`gitolite-migrated.dl`, sans instantane) n'est pas
reconnue : elle est a regenerer en droits comme donnees.

Le plan fait compiler la politique par le moteur et calcule le pire cas de
son execution : le nombre de groupes d'un utilisateur, imbrications
comprises et `all` compris, que `effective_group_member` contient pour une
requete. Il rend
`budget`, les comptes du moteur, les bornes et ce pire cas ; un budget
depasse est une entree non migrable, `policy budget exceeded: BUDGET N
requested, limit L`, et `budget.failure` la decrit en machine. Rien n'est
applique. La politique generee est rechargee par le moteur avant d'etre
publiee.

### Perimetre de la fidelite mesuree

La fidelite a Gitolite 3.6.15 est mesuree sur l'ecriture : mise a jour
(`W`), mise a jour forcee (`+`) et ecriture sans ref (`any`), comparees a
Gitolite lui-meme et a un oracle calibre sur lui. La lecture n'est pas
comparee, et elle differe :

- **Lecture accordee par un droit de ref seul.** Avec seulement
  `RW+ refs/heads/feature/ = alice`, Gitolite laisse alice lire le depot
  (`R any`) ; Git Core lui refuse la lecture et ne lui laisse que
  l'ecriture. Plus strict, en litteral comme en regex. Un droit `R`, `RW`
  ou `RW+` sans refex sur le depot donne la lecture dans les deux.

C'est un ecart connu, a corriger a part.

`authorize push` en ligne de commande decide les attributions de ref quand
il recoit le type de mise a jour, `--update-kind
create|fast_forward|force|delete`, celui que le hook, le shell et
l'executeur transmettent. Sans lui, une attribution de ref n'accorde rien
et un `push` n'est decide que par ses refus.

L'objectif raisonnable n'est pas la compatibilite syntaxique complete. Il faut
fournir une bibliotheque de politiques typees couvrant les VREF utiles, puis
faire migrer explicitement chaque construction reconnue. Toute construction
inconnue doit continuer a bloquer l'application.

### Face a Forgejo

Maelys Git Core ne doit pas chercher a reproduire Forgejo dans ce depot. Son
avantage defendable est d'etre un noyau local petit, auditable, deterministe et
independant de la disponibilite du SaaS. Forgejo reste tres loin devant sur le
produit collaboratif, l'identite Web, l'API publique, les integrations et la
CI.

Le noyau PR actuel est une bonne frontiere : Maelys prepare et applique les
mutations Git en les reautorisant ; une forge separee conserve l'etat durable
des PR, revues, checks et utilisateurs.

Le 15 octobre 2026, l'objectif est fixe de prendre en charge a terme les
pull requests et la CI, pour ne plus dependre d'une forge tierce. Cela ne
change pas cette frontiere : l'etat des PR et l'execution de la CI seront des
services separes, construits sur ce noyau, sur un runtime de confinement
d'execution et sur l'acquisition d'images ; ni l'un ni l'autre n'entre dans
la bibliotheque C. Le noyau leur doit trois choses qu'il n'a pas encore : un
recu de decision verifiable, des evenements de push horodates et identifies,
et Git en HTTP.

## Ordre recommande

1. **P0 - definir l'etat durable de PR cote forge** : le noyau local sait
   maintenant mettre en quarantaine, verifier et promouvoir les objets d'un
   fork ; il reste a modeliser ouverture, synchronisation, revue, checks,
   fermeture et fusion dans le service de forge.
2. **P1 - definir la CI** : declaration des pipelines, declenchement par les
   evenements de push et de PR, execution confinee, statuts rendus au service
   de PR comme gates. Service separe ; le noyau n'y gagne que des evenements
   et des gates.
3. **P1 - rendre les decisions transportables** : recu versionne (cycle
   GIT-C02, specifie), precede d'erreurs de politique structurees (cycle
   GIT-C04, specifie) ; propagation de l'annulation dans les processus Git.
4. **P1 - terminer la parite Gitolite selectionnee** : publication
   transactionnelle des sous-politiques deleguees, includes confines, budget
   de regles des prefixes (cycle GIT-C03) et orchestration distante des
   miroirs. Continuer a refuser toute construction dont la semantique ne peut
   pas etre preservee.
5. **P1 - definir le contrat de forge** : API de comptes/equipes, etat PR,
   webhooks sortants et smart HTTP Git, sans introduire ces responsabilites
   dans la bibliotheque C.
6. **P2 - construire le produit collaboratif** : UI, commentaires, issues,
   wiki, releases, LFS et notifications. Registry de paquets ensuite.

## Frontiere de durcissement actuelle

- Git reste l'unique implementation du stockage d'objets et des references.
- Chaque commande Git lancee dispose d'une echeance de 120 secondes.
- Les flux captures ont des quotas explicites de memoire ou de spool.
- Les commits produits pour une PR sont canoniques et deterministes.
- L'application recalcule l'OID prepare et l'empreinte de l'ensemble des
  politiques Datalog.
- Les gates fournis par la forge sont reevalues au moment de l'application.
- Les cles publiques SSH sont decodees et validees structurellement avant
  publication.
- L'inspection des blobs est groupee, bornee et partagee entre push et PR.
- Une application de PR peut mettre a jour target, head et resultat dans une
  seule transaction Git.
- Une PR de fork est inspectee dans une quarantaine jetable ; son identite, son
  OID de branche et ses budgets sont reverifies avant promotion.

## Pistes Maelys Datalog reportees

Le moteur fournit deja des magasins de faits bornes, une resolution
deterministe, les comparaisons d'entiers et des explications de preuve. Les
ameliorations les plus rentables restent :

- une API batch pour plusieurs jeux de faits de requete independants ;
- des hooks explicites d'annulation et d'echeance.

Fait depuis : une session reutilisable par politique, dont l'EDB est remplace
a chaque requete sans recompiler les regles (cycle GIT-C01) ; des diagnostics
de capacite qui nomment le budget depasse, au chargement comme sur un lot
d'entree refuse, fournis par maelys-datalog 0.23.1, que Git Core exposera au
cycle GIT-C04. Le recu de decision se construit dans Git Core sur les vues
d'explication du moteur (cycle GIT-C02).

Le hook receive streame deja les enregistrements Git. Un solveur Datalog
streaming n'est pas necessaire pour la correction : sessions reutilisables et
evaluation batch apporteraient l'essentiel du gain sans affaiblir les bornes
deterministes.

## Sources officielles

- Gitolite : [vue d'ensemble](https://gitolite.com/gitolite/overview.html),
  [VREF, partie 1](https://gitolite.com/gitolite/vref.html),
  [VREF, partie 2](https://gitolite.com/gitolite/vref-2.html),
  [depots dynamiques](https://gitolite.com/gitolite/wild.html),
  [delegation](https://gitolite.com/gitolite/deleg.html) et
  [mirroring](https://gitolite.com/gitolite/mirroring.html).
- Forgejo v16 : [guide utilisateur](https://forgejo.org/docs/latest/user/),
  [protection des branches et tags](https://forgejo.org/docs/latest/user/repository/protection/),
  [guide administrateur](https://forgejo.org/docs/latest/admin/),
  [Actions](https://forgejo.org/docs/latest/user/actions/overview/) et
  [packages](https://forgejo.org/docs/latest/user/packages/).
