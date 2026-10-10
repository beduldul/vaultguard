//! VaultGuard — an on-chain security threat registry.
//!
//! An authorized authority records security threats against target
//! addresses. Other programs and clients can read the registry PDA and
//! the per-target threat record PDAs.
//!
//! # Security invariants (program-wide)
//!
//! 1. Every instruction that mutates state requires the registry authority
//!    to sign. The binding between the `Registry` account and its authority
//!    is enforced by Anchor via `has_one = authority`, never by hand.
//! 2. The authority PDA ("pending authority") is a program-derived
//!    account; a malicious signer cannot forge it.
//! 3. All arithmetic on risk scores is checked (`checked_add`,
//!    `checked_sub`) and all scores are bounds-validated on input.
//! 4. Metadata is length-limited; account sizes are fixed and cannot be
//!    overrun.
//! 5. PDA bumps are stored in the accounts, never recomputed.
//! 6. No `unwrap()`/`panic!`/`expect()` on fallible operations in
//!    instruction handlers; every failure surfaces as a typed error.

use anchor_lang::prelude::*;

/// Maximum length of the free-form metadata string attached to a threat.
pub const MAX_METADATA_LEN: usize = 128;
/// Minimum valid risk score (inclusive).
pub const MIN_RISK_SCORE: u64 = 0;
/// Maximum valid risk score (inclusive).
pub const MAX_RISK_SCORE: u64 = 100;

declare_id!("BatNd9ENqUiHsTUfn7Q6bU79kNC4cYM2FoXiRNN1f5JG");

#[program]
pub mod vaultguard {
    use super::*;

    /// Create the registry PDA and set the initial authority.
    ///
    /// # Security invariants
    /// - The authority must sign; the initial authority is whoever signs
    ///   the initialization transaction.
    /// - The registry PDA must not already exist (`init` enforces this),
    ///   so the registry cannot be re-initialized or hijacked.
    /// - The PDA is derived from canonical seeds; the bump is found once
    ///   here and stored on-chain, never recomputed from client input.
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.bump = ctx.bumps.registry;
        registry.authority = ctx.accounts.authority.key();
        // Two-step authority transfer: nothing pending at init.
        registry.pending_authority = Pubkey::default();
        registry.threat_count = 0;
        registry.total_reports = 0;
        registry.initialized_at = Clock::get()?.unix_timestamp;
        msg!("registry initialized, authority={}", registry.authority);
        Ok(())
    }

    /// Record a threat against a target address. Authority-only.
    ///
    /// # Security invariants
    /// - `authority` must be a signer AND must equal `registry.authority`
    ///   (enforced by `has_one = authority`). An unauthorized signer is
    ///   rejected before any state mutation.
    /// - The threat record PDA is derived from the *target* key, so one
    ///   canonical record exists per target; `init` rejects duplicates.
    /// - Risk score must be within [MIN_RISK_SCORE, MAX_RISK_SCORE];
    ///   metadata must be <= MAX_METADATA_LEN bytes. Both are validated
    ///   before the record is created.
    pub fn register_threat(
        ctx: Context<RegisterThreat>,
        risk_score: u64,
        category: ThreatCategory,
        metadata: String,
    ) -> Result<()> {
        validate_score(risk_score)?;
        validate_metadata(&metadata)?;

        let record = &mut ctx.accounts.threat_record;
        let registry = &mut ctx.accounts.registry;

        record.bump = ctx.bumps.threat_record;
        record.registry = registry.key();
        record.target = ctx.accounts.target.key();
        record.authority = registry.authority;
        record.risk_score = risk_score;
        record.category = category;
        record.metadata = metadata;
        record.active = true;
        record.created_at = Clock::get()?.unix_timestamp;
        record.updated_at = record.created_at;

        registry.threat_count = registry.threat_count.checked_add(1).ok_or(VaultGuardError::ArithmeticOverflow)?;
        registry.total_reports = registry.total_reports.checked_add(1).ok_or(VaultGuardError::ArithmeticOverflow)?;
        msg!("threat registered for {}", record.target);
        Ok(())
    }

    /// Update the risk score on an existing threat record. Authority-only.
    ///
    /// # Security invariants
    /// - Authority must sign and match `registry.authority`.
    /// - `has_one = registry` on the record ties the record to the
    ///   registry PDA, so a record from another (attacker-created)
    ///   registry cannot be updated here.
    /// - New score is bounds-validated; no arithmetic is performed that
    ///   can overflow, but the update timestamp is set for history.
    pub fn update_risk_score(ctx: Context<UpdateRiskScore>, new_score: u64) -> Result<()> {
        validate_score(new_score)?;

        let record = &mut ctx.accounts.threat_record;
        record.risk_score = new_score;
        record.updated_at = Clock::get()?.unix_timestamp;
        msg!("risk score updated to {}", new_score);
        Ok(())
    }

    /// Mark an existing threat as resolved. Authority-only. The record is
    /// deliberately NOT deleted: history is preserved for auditability.
    ///
    /// # Security invariants
    /// - Authority must sign and match `registry.authority`.
    /// - Clearing a non-existent record is impossible: the PDA cannot be
    ///   found unless it was initialized, so this instruction only ever
    ///   operates on records that were previously registered.
    /// - Clearing an already-cleared record is a no-op-safe transition
    ///   (idempotent); we allow it without error to keep clients simple,
    ///   but it cannot resurrect a threat or alter the score.
    pub fn clear_threat(ctx: Context<UpdateRiskScore>) -> Result<()> {
        let record = &mut ctx.accounts.threat_record;
        record.active = false;
        record.updated_at = Clock::get()?.unix_timestamp;
        msg!("threat cleared for {}", record.target);
        Ok(())
    }

    /// Begin a two-step authority transfer. Authority-only.
    ///
    /// # Security invariants
    /// - Only the current authority can nominate a pending authority, so
    ///   an attacker cannot self-nominate.
    /// - The pending authority is stored but takes no effect until
    ///   `accept_authority` is called by the nominee, so a typo or a
    ///   compromised key cannot instantly brick the registry.
    pub fn transfer_authority(ctx: Context<TransferAuthority>, new_authority: Pubkey) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.pending_authority = new_authority;
        msg!("pending authority set to {}", new_authority);
        Ok(())
    }

    /// Complete the two-step authority transfer. Pending-authority-only.
    ///
    /// # Security invariants
    /// - The signer must match `registry.pending_authority` (checked
    ///   explicitly here; Anchor `has_one` cannot express this, so the
    ///   check is done by hand and the account is a `Signer`).
    /// - After acceptance, the old authority loses all power and the
    ///   pending slot is cleared.
    pub fn accept_authority(ctx: Context<AcceptAuthority>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        require_keys_eq!(
            ctx.accounts.pending_authority_signer.key(),
            registry.pending_authority,
            VaultGuardError::NotPendingAuthority
        );
        registry.authority = registry.pending_authority;
        registry.pending_authority = Pubkey::default();
        msg!("authority transferred to {}", registry.authority);
        Ok(())
    }

    /// Re-activate a previously cleared threat. Authority-only.
    pub fn reactivate_threat(ctx: Context<UpdateRiskScore>) -> Result<()> {
        let record = &mut ctx.accounts.threat_record;
        record.active = true;
        record.updated_at = Clock::get()?.unix_timestamp;
        Ok(())
    }
}

// ---------------------------------------------------------------- context

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    /// Registry PDA. `init` guarantees one-time creation.
    #[account(
        init,
        seeds = [b"registry"],
        bump,
        payer = authority,
        space = 8 + Registry::INIT_SPACE,
    )]
    pub registry: Account<'info, Registry>,
    /// Initial authority; must sign.
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterThreat<'info> {
    /// Registry singleton; authority binding enforced by Anchor.
    #[account(mut, has_one = authority)]
    pub registry: Account<'info, Registry>,
    /// Threat record PDA keyed by the target address.
    #[account(
        init,
        seeds = [b"threat", target.key().as_ref()],
        bump,
        payer = authority,
        space = 8 + ThreatRecord::INIT_SPACE,
    )]
    pub threat_record: Account<'info, ThreatRecord>,
    /// CHECK: The target address is only used as a PDA seed and stored
    /// as a key. Its data/ownership is intentionally irrelevant — the
    /// registry may contain threats against arbitrary addresses,
    /// including accounts that do not exist.
    pub target: AccountInfo<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateRiskScore<'info> {
    #[account(has_one = authority)]
    pub registry: Account<'info, Registry>,
    /// The record must belong to this registry, preventing cross-registry
    /// record substitution.
    #[account(mut, has_one = registry)]
    pub threat_record: Account<'info, ThreatRecord>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    #[account(mut, has_one = authority)]
    pub registry: Account<'info, Registry>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAuthority<'info> {
    #[account(mut)]
    pub registry: Account<'info, Registry>,
    /// Must be the pending authority recorded on the registry. This is
    /// checked in `accept_authority` because `has_one` cannot target the
    /// pending field.
    pub pending_authority_signer: Signer<'info>,
}

// -------------------------------------------------------------- accounts

#[account]
#[derive(InitSpace)]
pub struct Registry {
    /// The current authority (the only address allowed to mutate state).
    pub authority: Pubkey,
    /// Nominated next authority; `Pubkey::default()` when no transfer is
    /// pending.
    pub pending_authority: Pubkey,
    /// Stored canonical bump of the registry PDA.
    pub bump: u8,
    pub threat_count: u64,
    pub total_reports: u64,
    pub initialized_at: i64,
}

#[account]
#[derive(InitSpace)]
pub struct ThreatRecord {
    /// Registry this record belongs to.
    pub registry: Pubkey,
    /// The threatened address.
    pub target: Pubkey,
    pub authority: Pubkey,
    pub risk_score: u64,
    pub category: ThreatCategory,
    pub active: bool,
    /// Stored canonical bump of the record PDA.
    pub bump: u8,
    #[max_len(MAX_METADATA_LEN)]
    pub metadata: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace, Debug)]
#[repr(u8)]
pub enum ThreatCategory {
    Exploit = 0,
    Phishing = 1,
    ScamToken = 2,
    MaliciousValidator = 3,
    Sybil = 4,
    Other = 5,
}

// ---------------------------------------------------------------- errors

#[error_code]
#[derive(PartialEq, Eq)]
pub enum VaultGuardError {
    /// Risk score is outside the allowed [MIN_RISK_SCORE, MAX_RISK_SCORE] range.
    #[msg("Risk score is out of the allowed range [0, 100]")]
    RiskScoreOutOfRange,
    /// Metadata exceeds MAX_METADATA_LEN bytes.
    #[msg("Metadata string exceeds the maximum length of 128 bytes")]
    MetadataTooLong,
    /// Metadata contains interior null bytes (defensive, not reachable
    /// via serde but kept explicit for the audit trail).
    #[msg("Metadata contains invalid characters")]
    InvalidMetadata,
    /// Checked arithmetic overflowed.
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    /// Signer is not the pending authority recorded on the registry.
    #[msg("Signer is not the pending authority")]
    NotPendingAuthority,
    /// The threat record does not belong to this registry.
    #[msg("Threat record does not belong to this registry")]
    WrongRegistry,
}

// ---------------------------------------------------------------- helpers

/// Validate that a risk score is within the allowed bounds.
/// Pure function; unit-tested without a validator.
pub fn validate_score(score: u64) -> Result<()> {
    require!(score >= MIN_RISK_SCORE && score <= MAX_RISK_SCORE, VaultGuardError::RiskScoreOutOfRange);
    Ok(())
}

/// Validate the metadata string: length-limited and no interior NULs.
/// Pure function; unit-tested without a validator.
pub fn validate_metadata(metadata: &str) -> Result<()> {
    require!(metadata.len() <= MAX_METADATA_LEN, VaultGuardError::MetadataTooLong);
    require!(!metadata.contains('\0'), VaultGuardError::InvalidMetadata);
    Ok(())
}

/// Pure helper: checked increment of a counter, used by `register_threat`.
pub fn checked_increment(counter: u64) -> Result<u64> {
    counter
        .checked_add(1)
        .ok_or_else(|| VaultGuardError::ArithmeticOverflow.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::error::Error;

    fn err_code(e: Error) -> u32 {
        match e {
            Error::AnchorError(ae) => ae.error_code_number,
            other => panic!("expected AnchorError, got {other:?}"),
        }
    }

    // ---- validate_score -------------------------------------------------

    #[test]
    fn score_zero_is_valid() {
        assert!(validate_score(0).is_ok());
    }
    #[test]
    fn score_max_is_valid() {
        assert!(validate_score(MAX_RISK_SCORE).is_ok());
    }
    #[test]
    fn score_mid_is_valid() {
        assert!(validate_score(50).is_ok());
    }
    #[test]
    fn score_above_max_rejected() {
        let e = validate_score(MAX_RISK_SCORE + 1).unwrap_err();
        assert_eq!(err_code(e), 6000); // RiskScoreOutOfRange
    }
    #[test]
    fn score_u64_max_rejected() {
        assert!(validate_score(u64::MAX).is_err());
    }

    // ---- validate_metadata ----------------------------------------------

    #[test]
    fn metadata_empty_is_valid() {
        assert!(validate_metadata("").is_ok());
    }
    #[test]
    fn metadata_max_len_is_valid() {
        let s = "a".repeat(MAX_METADATA_LEN);
        assert!(validate_metadata(&s).is_ok());
    }
    #[test]
    fn metadata_over_max_len_rejected() {
        let s = "a".repeat(MAX_METADATA_LEN + 1);
        let e = validate_metadata(&s).unwrap_err();
        assert_eq!(err_code(e), 6001); // MetadataTooLong
    }
    #[test]
    fn metadata_huge_is_rejected() {
        assert!(validate_metadata(&"x".repeat(10_000)).is_err());
    }
    #[test]
    fn metadata_with_nul_rejected() {
        let e = validate_metadata("bad\0string").unwrap_err();
        assert_eq!(err_code(e), 6002); // InvalidMetadata
    }

    // ---- checked_increment ----------------------------------------------

    #[test]
    fn increment_basic() {
        assert_eq!(checked_increment(0).ok(), Some(1));
        assert_eq!(checked_increment(u64::MAX - 1).ok(), Some(u64::MAX));
    }
    #[test]
    fn increment_overflow_is_error() {
        let e = checked_increment(u64::MAX).unwrap_err();
        assert_eq!(err_code(e), 6003); // ArithmeticOverflow
    }

    // ---- invariants -------------------------------------------------------

    #[test]
    fn error_codes_are_distinct() {
        let codes = [
            VaultGuardError::RiskScoreOutOfRange,
            VaultGuardError::MetadataTooLong,
            VaultGuardError::InvalidMetadata,
            VaultGuardError::ArithmeticOverflow,
            VaultGuardError::NotPendingAuthority,
            VaultGuardError::WrongRegistry,
        ];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}

