# Releasing maelys-git-core

This repository publishes through its own mechanism, not through the
maelys-release workflows. The socle wrote this file once because it was
missing; it belongs to this repository now, and describing that mechanism
here is the point. What follows is the part the Maelys conventions fix for
every repository, whatever publishes it (`docs/conventions.md` of
maelys-release).

1. On `main`: `VERSION` = `X.Y.Z`, a dated `CHANGELOG.md` entry
   `## X.Y.Z — YYYY-MM-DD`, generated documentation regenerated, and this
   repository's own checks green on the exact commit.
2. Merge through a pull request with green CI.
3. `maelys-release check .` from any maelys-release checkout: the conventions
   verdict must be green. The release verdict does not apply here.
4. `git tag -s vX.Y.Z -m "maelys-git-core X.Y.Z" && git push origin vX.Y.Z`.
5. Publish with this repository's own mechanism. **Describe it here**: the
   workflow or command that runs, what it builds, where it publishes, and
   what a maintainer checks afterwards.
6. A published tag is never moved, recreated or force-pushed. A publication
   that failed is replayed on the existing tag; a defect found after a tag
   is a new version.

## Mechanism of this repository

No release has been published and no mechanism exists yet: this repository
has no remote and no `maelys-release.conf`. The conventions above are adopted
first so that the first release starts from them. When the repository gains a
remote in the `maelys-dev` organisation, the intended path is the socle's own
workflows (`maelys-release adopt` with a `maelys-release.conf` declaring
`[check]` legs and `[dependencies] apart`), replacing this section.
