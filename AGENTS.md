# Working in this repository

## Always commit

**Commit after every change.** Do not leave work sitting in the working tree —
an uncommitted change is one interrupted session away from being lost, and it
is invisible to anyone reviewing what the repository actually says.

Commit in focused pieces rather than one omnibus commit. The history here is
one-change-per-commit and reads as prose:

```
Portal: tie a bridged channel to the guild that authorized it
Bridge: put the caps an inbound rumor meets on the paths it takes
Concord: make a ban take authority over its target, not just the BAN bit
```

The subject names the package (`Portal:`, `Bridge:`, `Concord:`, `Docs:`,
`Deps:`) and says what changed in the indicative mood. The body says *why* —
the attack that motivated it, the failure it prevents, the thing that was
silently wrong. Assume the reader can read the diff and cannot read your mind.

Run the tests before committing:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets   # keep it at zero warnings
```

Suites needing Postgres skip themselves when `DATABASE_URL` is unreachable, so
a bare `cargo test` is meaningful but not complete. To run them for real, point
`DATABASE_URL` at a throwaway database — a container on a spare port is enough,
and migrations bring it up from empty.

## Comments earn their place

Comments here explain *why*, and specifically why the obvious alternative is
wrong. Several of them are the only record of an attack that was closed. Match
that: when you fix something security-relevant, leave behind the reasoning that
makes the fix hard to undo by accident.

## Two things are shared, and changing them diverges

- **`crates/concord` is the protocol kernel**, a port of the Armada client's,
  which folds the same events, and pinned to it by `tools/vectors`. Changing
  which editions are *admissible* does not harden the system — it makes the bridge and Armada disagree about
  who is authorized. Additive signals (reporting an entity as incomplete) are
  safe; changing an authorization gate is a protocol decision that belongs
  upstream in the CORD specs first.
- **The popup handoff contract** (`/api/auth/discord?mode=popup`,
  `/api/auth/claim`) is consumed by the Armada client at `https://armada.buzz`,
  which is a separate codebase. Do not change its shape without shipping the
  client side first.

## Migrations run at boot, inside a transaction

`migrate()` runs on every portal start, so a migration that fails takes the
service down with it. A constraint added over existing data must resolve any
rows that would violate it *before* creating it, and should do so
non-destructively — see `017_one_bridge_per_discord_channel.sql`, which pauses
the losers rather than deleting them.

## Deploying

`DEPLOY.md` is the runbook. It is deliberately not in git: this repository is
public, and that file names hosts and paths.
