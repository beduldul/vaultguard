# VaultGuard

An on-chain security threat registry for Solana, written in Anchor.

An authorized **authority** records security threats (a risk score, a
category, and short metadata) against arbitrary target addresses. Other
programs and clients can read the registry and the per-target threat
records directly on-chain — this is the Solana port of the EVM
`ChainGuardRegistry` concept.

## Build & test

```sh
anchor build
anchor test        # spins up a local validator
cargo test -p vaultguard   # pure-logic unit tests, no validator needed
```

Toolchain: Anchor 0.30.1, Solana CLI (Agave) 4.x, Rust stable.

## Instructions

All mutating instructions are authority-gated. The authority binding is
enforced by Anchor (`has_one = authority`), not by hand, except
`accept_authority`, where the pending-authority check is explicit.

| Instruction | Signer | Constraint |
|---|---|---|
| `initialize_registry` | initial authority | `init` on the registry PDA — cannot be re-run |
| `register_threat(risk_score, category, metadata)` | authority | `has_one = authority` on registry; score bounds [0,100]; metadata ≤ 128 bytes |
| `update_risk_score(new_score)` | authority | `has_one = authority` on registry, `has_one = registry` on record; score bounds |
| `clear_threat` | authority | same account constraints; marks `active = false`, never deletes |
| `reactivate_threat` | authority | same; sets `active = true` |
| `transfer_authority(new_authority)` | authority | step 1 of two-step transfer; stores pending authority |
| `accept_authority` | pending authority | signer must equal `registry.pending_authority` |

## Account layout (IDL-derived)

### Registry — PDA `["registry"]`

| Field | Type | Meaning |
|---|---|---|
| `authority` | Pubkey | only address allowed to mutate state |
| `pending_authority` | Pubkey | nominee; default pubkey when none pending |
| `bump` | u8 | stored canonical PDA bump |
| `threat_count` | u64 | active+cleared records ever created |
| `total_reports` | u64 | total registrations |
| `initialized_at` | i64 | unix timestamp |

### ThreatRecord — PDA `["threat", <target key>]`

| Field | Type | Meaning |
|---|---|---|
| `registry` | Pubkey | owning registry (has_one enforced) |
| `target` | Pubkey | the threatened address |
| `authority` | Pubkey | authority at creation time |
| `risk_score` | u64 | 0–100 |
| `category` | u8 enum | Exploit, Phishing, ScamToken, MaliciousValidator, Sybil, Other |
| `active` | bool | false once cleared (history preserved) |
| `bump` | u8 | stored canonical PDA bump |
| `metadata` | String (max 128 B) | free-form note |
| `created_at` / `updated_at` | i64 | unix timestamps |

### Reading records

The account structures derive `AnchorSerialize`/`AnchorDeserialize`, so
any client can deserialize them:

```ts
const record = await program.account.threatRecord.fetch(threatPda);
```

Off-chain, the generated IDL (`target/idl/vaultguard.json`) plus
`anchor dpi`/`anchor client` tooling, or plain Borsh with the layout
above, both work. The PDAs are canonical and deterministic, so a client
can derive the record address for any target without an RPC lookup:

```
PDA(["threat", target_key], program_id)
```

## Security model

See [SECURITY.md](./SECURITY.md). In short: only the registry authority
can mutate state; scores are bounds-checked; metadata is length-limited;
all counter arithmetic is checked; PDA bumps are stored; clearing keeps
history. The trust assumption — that the authority is honest — is
explicit and uneliminable by design; see the threat model.

## License

MIT.
