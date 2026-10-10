# VaultGuard — Security Model & Threat Model

## What the program is

A registry. An authority tags addresses with risk scores and categories.
It is a source of **opinions signed by the authority**, not ground truth.

## Who can do what

| Actor | Capability |
|---|---|
| Registry authority | create/update/clear threat records, initiate authority transfer |
| Pending authority | accept the transfer (step 2) |
| Anyone | initialize... nothing. Read every account. Trigger nothing. |
| Anyone | attempt any mutation — rejected by `Signer` + `has_one` checks |

## Trust assumptions (honest)

1. **The authority is trusted by everyone who consumes the registry.**
   This is the core assumption and it is *not* removed by this program.
   If the authority is malicious, it can mark honest addresses as
   dangerous and dangerous addresses as safe. Consumers must decide how
   much to trust the authority key; the program cannot do that for them.
2. **Solana runtime guarantees are assumed** (no validator-level
   reordering attacks, account data integrity). Standard assumption.
3. **The target account is not verified.** A threat record binds a key,
   not the underlying system behind that key. If an attacker rotates a
   program's upgrade authority, history for the old key says nothing
   about the new one.

## If the authority key is compromised

- The attacker gains full write access: forge or clear any threat.
- **Mitigation already built in:** authority transfer is two-step. A
  compromise does not let the attacker transfer authority to themselves
  and lock out the owner silently — but if the attacker *is* the current
  authority, they can nominate and accept with their own key. Two-step
  protects against *accidental* loss and honest-mistake bricking, not
  against an attacker who already holds the key.
- **What would help and is deliberately out of scope here:** a
  multisig authority (e.g., Squads), a time-locked authority change, or
  an on-chain governance authority. Integrators should wrap this program
  behind one of those before deploying with real value at stake.
- **Recovery:** the new (honest) authority can re-record corrected
  threats; cleared/incorrect records cannot be deleted by anyone, so
  false data can be superseded but never erased.

## What the program deliberately does not protect against

- **Authority misbehavior** (above).
- **Spam/quality of the registry.** Anyone can ask the authority to
  register anything; there is no challenge period, no staking, no
  dispute mechanism.
- **Front-running of `transfer_authority`.** The nominee is public in
  the pending slot. This is harmless (only the nominee can accept) but
  worth knowing.
- **Historical integrity of edits.** `update_risk_score` overwrites the
  score in place. Only `created_at`/`updated_at` and the fact a record
  was cleared (`active = false`) preserve history. A full audit log of
  every score change would require an append-only event account, which
  this version does not include.
- **Sybil targets.** Nothing prevents records against fresh keys.

## Concrete security invariants enforced on-chain

1. Every mutating instruction requires the registry authority's
   signature, enforced by Anchor `has_one = authority` (and explicitly
   for `accept_authority`).
2. The registry PDA can be initialized exactly once (`init`); the
   program cannot be re-deployed over an existing registry state.
3. Threat record PDAs are derived from the target key, so one canonical
   record exists per target and cannot be duplicated or substituted
   cross-registry (`has_one = registry` on the record).
4. Risk scores are validated to `[0, 100]` on every write path.
5. Metadata is capped at 128 bytes; account sizes are fixed at init, so
   no account can be overrun.
6. All counter arithmetic is `checked_add`; the release profile enables
   `overflow-checks` as a second layer.
7. Authority transfer requires the nominee's signature to complete
   (two-step).
8. No `unwrap()`/`expect()` on fallible operations in instruction
   handlers; all failures are typed error codes with documented
   messages.

## Verifiability

- `cargo test -p vaultguard` — pure-logic tests (score bounds, metadata
  limits, checked arithmetic) run without a validator.
- `anchor test` — end-to-end tests including the critical class:
  *an unauthorized caller is rejected on every authority-only
  instruction*.
