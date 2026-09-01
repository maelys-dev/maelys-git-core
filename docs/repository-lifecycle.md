# Repository lifecycle

Maelys Git Core provides local, agent-readable repository administration
without physically deleting Git objects.

## Inventory and inspection

`repo list ROOT` recursively inventories direct bare repositories and excludes
the reserved `.maelys-git` namespace. `--include-stored` also returns archive
and recoverable-trash entries with their stable storage identifiers.

`repo inspect ROOT REPOSITORY` returns the direct path, device/inode identity,
symbolic HEAD, resolved HEAD object, ref count, object count, and approximate
Git object bytes. It rejects repository paths containing symbolic links.

## Reviewed transitions

The mutating commands are:

- `repo rename ROOT SOURCE TARGET`;
- `repo archive ROOT REPOSITORY STORAGE_ID`;
- `repo delete ROOT REPOSITORY STORAGE_ID`;
- `repo restore ROOT STORAGE_ID --from archive|trash [--as REPOSITORY]`.

They are read-only plans unless `--apply` is supplied. A plan returns
`precondition.sourceIdentity`. Apply must echo that value through
`--expected-source-identity`; replacing the source directory between plan and
apply therefore fails closed.

Rename and restore use a no-replace filesystem rename on macOS. Archive and
delete first reserve a mode-0700 storage entry and then move the repository
within the same repository root. Storage is structured as:

```text
ROOT/.maelys-git/
├── archive/ID/
│   ├── repository-name
│   └── repository.git/
└── trash/ID/
    ├── repository-name
    └── repository.git/
```

The internal component is rejected by repository-name validation, so SSH Git
services and deploy keys cannot address stored repositories. Existing internal
directories must be owned by the current agent account and may not be group or
world writable.

`repo delete` is intentionally recoverable: it moves the complete bare
repository to `trash`. There is no irreversible purge command in this release.

Every plan/apply result contains a versioned event matching
`protocol/repository-events-v1.schema.json`. The local CLI does not append the
event to an external log on its own; the invoking agent or forge can commit the
successful result and event in its own durable transaction.
