# Nelori's provenance log

Nelori seals a provenance record for each original work sold through it, and gives the artist and the collector a copy that checks without Nelori. Two things a careful reader of such a copy takes from Nelori and not from the copy: the keys Nelori signs with, and the list of a work's versions, which tells the latest from an earlier one.

Nelori publishes both at nelori.com. This repository is the second place for them, kept apart from the site, so that:

- a copy still checks in full if nelori.com is gone, and
- taking over nelori.com is not enough to name a forger's key or to drop a version.

It is still Nelori's. It guards against losing or losing control of the site, not against Nelori. Its history is public, and anyone may keep a clone.

## What is here

| File | What it holds |
|---|---|
| `keys.json` | Every Ed25519 public key Nelori has signed provenance records with. Changed by hand only. |
| `heads/<work>.json` | A sold work's list of versions, signed by Nelori: each version's number, the SHA-256 it is sealed by and the date it runs through. |
| `state.json` | Where the last run stopped, and any work whose list it refused. |
| `mirror.mjs` | The program that follows nelori.com. |
| `verify.mjs` | The checker every copy carries. `mirror.mjs` uses it to check signatures. |

Nothing here says what a record says: no name, price, image or statement. What is public here, for good, is which works have a record, how many versions each has, and when each was made.

## The rules

`mirror.mjs` runs every three hours and refuses anything that breaks one of these. A refusal is not written, and fails the run.

1. **A key comes in by hand.** The program never adds a key to `keys.json` and never removes one. If nelori.com lists a key this log does not hold, the run fails and says so.
2. **A list is kept only when a key in `keys.json` signed it.**
3. **A list only grows.** A version kept here is never changed or dropped.

## Checking a copy against this log

The checker in a copy asks both places when told to:

```
node verify.mjs --ask
```

or tick "Ask Nelori" in the copy's `verify.html`. A key that only one place lists does not count as Nelori's.

## When Nelori changes its key

Add the new public key to `keys.json` beside the earlier ones, in a commit made by a person at Nelori. Until then the run fails, and a copy signed with the new key checks as incomplete.
