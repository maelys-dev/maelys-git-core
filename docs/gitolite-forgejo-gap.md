# Matrice concurrentielle : Maelys Git Core, Gitolite et Forgejo

Etat verifie le 1er septembre 2026. La comparaison porte sur le code present
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
| Autorisation | Groupes d'utilisateurs | **Complet** dans les politiques ; migration limitee aux groupes plats | **Complet** : groupes, inclusions, macros, LDAP extensible | **Complet** : utilisateurs, organisations et equipes | P1 pour l'administration dynamique |
| Autorisation | Regles par branche, tag et type de mise a jour | **Complet** : faits `ref_kind`, `update_kind`, protections et deny prioritaire | **Complet** : refex, creation, suppression, rewind et ordre des regles | **Complet** : protections de branches et tags, glob/regex selon le type | Acquis pour le noyau |
| Autorisation | Regles selon les fichiers modifies | **Complet** : tous les changements sont streams, sans plafond historique de 64 chemins | **Complet** : `VREF/NAME` | **Partiel** : protections de refs, sans moteur general de faits par chemin equivalent | Avantage Maelys |
| Autorisation | Renommages et double chemin ancien/nouveau | **Complet** : `path` et `old_path` | **Partiel** : le VREF expose les noms touches, sans domaine type de renommage equivalent | **Partiel** : pas de domaine de politique general equivalent | Avantage Maelys |
| Autorisation | Faits sur objets Git | **Complet** : taille, mode, binaire, symlink, submodule et pointeur LFS | **Partiel** : VREF livres pour compte, nom, type et taille de nouveaux binaires ; extensions possibles | **Partiel** : controles integres cibles, sans faits composables equivalents | Avantage Maelys |
| Autorisation | Identite et signature des commits | **Complet** : email, etat, empreinte, identite et confiance injectes en Datalog | **Partiel/extensible** : `EMAIL-CHECK` livre et VREF personnalises | **Complet** : verification et politiques de signature integrees | Acquis |
| Autorisation | Quotas sur une transaction multi-ref | **Complet** : commits, chemins, octets et inspection cumules sur tout le receive | **Partiel** : `COUNT` et autres VREF sont principalement evalues par mise a jour de ref | **Partiel** : quotas et limites integres, sans domaine Datalog transactionnel equivalent | Avantage Maelys |
| Autorisation | Extension de la politique | **Complet** : regles Datalog versionnees et inspecteurs C bornes | **Complet** : vaste ecosysteme VREF, triggers et commandes | **Partiel** : hooks et code de la forge, moins adaptes aux politiques locales declaratives | P1 : bibliotheque de politiques |
| Audit | Explication et preuve d'une decision | **Partiel** : explications du solveur et empreinte de politique ; recu compact versionne encore absent | **Partiel** : test et diagnostic de regles, sans preuve declarative equivalente | **Partiel** : motifs fonctionnels et journaux, sans preuve de politique equivalente | P1 : decision receipt |
| Cles | Cles utilisateur et deploy keys | **Complet** : compilation atomique, validation, portee depot, lecture seule, expiration et revocation | **Complet** pour les cles utilisateur ; deploy keys specialisees a construire par convention/extension | **Complet** | P1 : rotation et attestation |
| Depots | Creation dynamique | **Complet** pour un nom exact autorise par Datalog | **Complet** : wild repos, regex, `CREATOR` et permissions dynamiques | **Complet** : UI/API et push-to-create configurable | P1 : patrons et proprietaire |
| Depots | Inventaire, inspection, renommage, archive, suppression recuperable et restauration | **Complet** : plan/apply et preconditions CAS | **Partiel** : administration centree configuration ; operations de cycle de vie souvent externes | **Complet** via la forge, avec modele plus riche | Acquis pour le local |
| Depots | Mirroring | **Absent** | **Complet** : maitres/copies, synchronisation et redirection avec limites documentees | **Complet** : miroirs de depot | P1 |
| Administration | Delegation d'administration | **Absent** | **Complet** : `subconf` et `VREF/NAME` | **Complet** : organisations, equipes et permissions | P1 |
| Migration | Import de configuration Gitolite | **Partiel** : groupes plats, depots exacts, `R`, `RW`, `RW+`; refus ferme du reste | Sans objet | Sans objet | P1 : mappings ref/VREF choisis |
| API | CLI normalise et decouvrable par un agent | **Complet** : enveloppe `agent-cli/v2`, catalogues JSON et plan/apply | **Partiel** : CLI et commandes SSH scriptables, sans contrat homogene equivalent | **Complet** : CLI, API HTTP et interface Web | Avantage Maelys pour l'automatisation locale |
| API | Agent distant durable | **Complet** dans son perimetre : HTTPS long-poll, journal SQLite, idempotence et outbox | **Absent** comme protocole integre | **Complet** autrement via API, webhooks et services de la forge | P1 : annulation et observabilite |
| Pull requests | Analyse de conflit et preparation FF/merge/squash | **Complet** dans un meme depot, deterministe et sans mutation pendant le plan | **Absent** | **Complet** | Acquis pour le noyau PR |
| Pull requests | Application atomique et reautorisee | **Complet** : CAS, empreinte de politique et transaction refs target/head/resultat | **Absent** | **Complet** dans le workflow de la forge | Avantage de surete a conserver |
| Pull requests | Approbations et checks obligatoires | **Partiel** : gates fournis par la forge et verifies localement, sans stockage durable | **Absent** | **Complet** | P0 : modele durable cote forge |
| Pull requests | PR entre forks et quarantaine d'objets | **Absent** | **Absent** | **Complet** | P0 avant forks |
| Collaboration | PR persistantes, revues, commentaires et historique | **Absent** | **Absent** | **Complet** | P0 cote forge |
| Collaboration | Issues, labels, projets et wiki | **Absent** | **Absent** | **Complet** | P2 cote forge |
| Distribution | Releases et stockage d'objets Git LFS | **Absent** : detection des pointeurs LFS seulement | **Absent** comme services integres | **Complet** | P2 |
| Integration | Webhooks et notifications | **Partiel** : evenements normalises, `post-receive` et outbox ; pas d'abonnements ni de livraison Web publique | **Extensible** : triggers/hooks, pas un produit webhook integre | **Complet** | P1 |
| Forge | Navigation Web, recherche et blame | **Absent** | **Absent** | **Complet** | P2 |
| Forge | Comptes Web, tokens, OAuth/OIDC/LDAP et SSO | **Absent** : identite SSH locale et bearer token d'agent seulement | **Partiel/extensible** : SSH principal, smart HTTP et LDAP pour groupes | **Complet** | P1 cote forge |
| Forge | CI integree | **Absent** | **Absent** | **Complet** : Forgejo Actions et runners separes | P2 |
| Forge | Registry de paquets | **Absent** | **Absent** | **Complet** | P3 |

## Lecture strategique

### Face a Gitolite

Maelys Git Core a deja depasse le modele ACL classique sur les points ou son
architecture Datalog apporte une vraie difference : composition de faits,
renommages, inspection d'objets, quotas globaux au receive et preconditions de
politique. Il ne depasse pas encore Gitolite comme outil d'exploitation : les
wild repos, la delegation, le mirroring et surtout l'ecosysteme VREF restent
des manques importants.

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

## Ordre recommande

1. **P0 - fermer le noyau PR** : quarantaine d'objets pour les forks,
   validation de joignabilite, quotas puis promotion atomique ; definir aussi
   la machine d'etats durable attendue de la forge.
2. **P1 - depasser Gitolite en exploitation** : patrons de depots avec
   proprietaire, delegation bornee, mirroring idempotent et bibliotheque de
   politiques equivalentes aux VREF selectionnes.
3. **P1 - rendre les decisions transportables** : recu versionne contenant
   empreinte de politique, requete, racine de preuve et budgets du solveur ;
   propagation de l'annulation dans les processus Git.
4. **P1 - definir le contrat de forge** : API de comptes/equipes, etat PR,
   webhooks sortants et smart HTTP Git, sans introduire ces responsabilites
   dans la bibliotheque C.
5. **P2 - construire le produit collaboratif** : UI, commentaires, issues,
   wiki, releases, LFS et notifications. Actions et registry viennent apres.

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

## Pistes Maelys Datalog reportees

Le moteur fournit deja des magasins de faits bornes, une resolution
deterministe, les comparaisons d'entiers et des explications de preuve. Les
ameliorations les plus rentables restent :

- une session reutilisable qui remplace l'EDB sans reconstruire les regles
  compilees pour chaque chemin ;
- une API batch pour plusieurs jeux de faits de requete independants ;
- un recu de decision compact et versionne contenant empreinte de politique,
  requete, racine de preuve et statistiques de budget ;
- des hooks explicites d'annulation et d'echeance.

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
