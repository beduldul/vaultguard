import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorError } from "@coral-xyz/anchor";
import { Vaultguard } from "../target/types/vaultguard";
import { expect } from "chai";

/**
 * VaultGuard end-to-end tests.
 *
 * The most important class here: every authority-only instruction must
 * reject a caller who is not the registry authority.
 */

const MAX_RISK_SCORE = 100;
const ERROR_CODES = {
  RiskScoreOutOfRange: 6000,
  MetadataTooLong: 6001,
} as const;

describe("vaultguard", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Vaultguard as Program<Vaultguard>;

  // Registry PDA is a singleton derived from a fixed seed.
  const [registryPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    program.programId
  );

  const authority = (provider.wallet as anchor.Wallet).payer;
  const impostor = anchor.web3.Keypair.generate();
  const newAuthority = anchor.web3.Keypair.generate();

  const targetKey = anchor.web3.Keypair.generate().publicKey;
  const threatPdaFor = (target: anchor.web3.PublicKey) =>
    anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("threat"), target.toBytes()],
      program.programId
    )[0];

  before(async () => {
    // Fund the impostor so its signature costs are valid transactions.
    const sig = await provider.connection.requestAirdrop(
      impostor.publicKey,
      anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig, "confirmed");
  });

  const expectAnchorError = (err: unknown, code: number) => {
    expect(err).to.be.instanceOf(AnchorError);
    if (err instanceof AnchorError) {
      expect(err.error.errorCode.number).to.equal(code);
    }
  };

  it("initializes the registry", async () => {
    await program.methods
      .initializeRegistry()
      .accounts({ registry: registryPda, authority: authority.publicKey })
      .rpc();

    const registry = await program.account.registry.fetch(registryPda);
    expect(registry.authority.equals(authority.publicKey)).to.be.true;
    expect(registry.pendingAuthority.equals(anchor.web3.PublicKey.default)).to
      .be.true;
    expect(registry.threatCount.toNumber()).to.equal(0);
  });

  it("cannot re-initialize the registry", async () => {
    const secondAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      secondAuthority.publicKey,
      anchor.web3.LAMPORTS_PER_SOL
    );
    // The PDA already exists: `init` must make this tx fail.
    try {
      await program.methods
        .initializeRegistry()
        .accounts({ registry: registryPda, authority: secondAuthority.publicKey })
        .signers([secondAuthority])
        .rpc();
      expect.fail("re-initialization should have failed");
    } catch (err) {
      expect(String(err)).to.match(/already in use|AccountAlreadyInitialized/i);
    }
  });

  describe("register_threat", () => {
    it("registers a threat on the happy path", async () => {
      const threatPda = threatPdaFor(targetKey);
      await program.methods
        .registerThreat(new anchor.BN(85), { exploit: {} }, "drainer contract interaction")
        .accounts({
          registry: registryPda,
          threatRecord: threatPda,
          target: targetKey,
          authority: authority.publicKey,
        })
        .rpc();

      const record = await program.account.threatRecord.fetch(threatPda);
      expect(record.riskScore.toNumber()).to.equal(85);
      expect(record.active).to.be.true;
      expect(record.target.equals(targetKey)).to.be.true;
      expect(record.metadata).to.equal("drainer contract interaction");

      const registry = await program.account.registry.fetch(registryPda);
      expect(registry.threatCount.toNumber()).to.equal(1);
    });

    it("rejects an unauthorized caller", async () => {
      const target = anchor.web3.Keypair.generate().publicKey;
      try {
        await program.methods
          .registerThreat(new anchor.BN(10), { phishing: {} }, "impostor report")
          .accounts({
            registry: registryPda,
            threatRecord: threatPdaFor(target),
            target,
            authority: impostor.publicKey,
          })
          .signers([impostor])
          .rpc();
        expect.fail("unauthorized register should have failed");
      } catch (err) {
        // has_one = authority => Anchor constraint error.
        expect(String(err)).to.match(/ConstraintHasOne|wrong authority|not the authority/i);
      }
    });

    it("rejects an out-of-range risk score", async () => {
      const target = anchor.web3.Keypair.generate().publicKey;
      try {
        await program.methods
          .registerThreat(new anchor.BN(MAX_RISK_SCORE + 1), { other: {} }, "score too high")
          .accounts({
            registry: registryPda,
            threatRecord: threatPdaFor(target),
            target,
            authority: authority.publicKey,
          })
          .rpc();
        expect.fail("out-of-range score should have failed");
      } catch (err) {
        expectAnchorError(err, ERROR_CODES.RiskScoreOutOfRange);
      }
    });

    it("rejects oversized metadata", async () => {
      const target = anchor.web3.Keypair.generate().publicKey;
      try {
        await program.methods
          .registerThreat(new anchor.BN(50), { other: {} }, "x".repeat(129))
          .accounts({
            registry: registryPda,
            threatRecord: threatPdaFor(target),
            target,
            authority: authority.publicKey,
          })
          .rpc();
        expect.fail("oversized metadata should have failed");
      } catch (err) {
        expectAnchorError(err, ERROR_CODES.MetadataTooLong);
      }
    });
  });

  describe("update_risk_score", () => {
    it("updates the score on the happy path", async () => {
      await program.methods
        .updateRiskScore(new anchor.BN(40))
        .accounts({
          registry: registryPda,
          threatRecord: threatPdaFor(targetKey),
          authority: authority.publicKey,
        })
        .rpc();

      const record = await program.account.threatRecord.fetch(
        threatPdaFor(targetKey)
      );
      expect(record.riskScore.toNumber()).to.equal(40);
    });

    it("rejects an unauthorized caller", async () => {
      try {
        await program.methods
          .updateRiskScore(new anchor.BN(10))
          .accounts({
            registry: registryPda,
            threatRecord: threatPdaFor(targetKey),
            authority: impostor.publicKey,
          })
          .signers([impostor])
          .rpc();
        expect.fail("unauthorized update should have failed");
      } catch (err) {
        expect(String(err)).to.match(/ConstraintHasOne|wrong authority|not the authority/i);
      }
    });

    it("rejects an out-of-range score", async () => {
      try {
        await program.methods
          .updateRiskScore(new anchor.BN(MAX_RISK_SCORE + 1))
          .accounts({
            registry: registryPda,
            threatRecord: threatPdaFor(targetKey),
            authority: authority.publicKey,
          })
          .rpc();
        expect.fail("out-of-range update should have failed");
      } catch (err) {
        expectAnchorError(err, ERROR_CODES.RiskScoreOutOfRange);
      }
    });
  });

  describe("clear_threat", () => {
    it("marks a record resolved but keeps it readable", async () => {
      await program.methods
        .clearThreat()
        .accounts({
          registry: registryPda,
          threatRecord: threatPdaFor(targetKey),
          authority: authority.publicKey,
        })
        .rpc();

      const record = await program.account.threatRecord.fetch(
        threatPdaFor(targetKey)
      );
      expect(record.active).to.be.false;
      expect(record.riskScore.toNumber()).to.equal(40); // history preserved
    });

    it("rejects an unauthorized caller", async () => {
      const target = anchor.web3.Keypair.generate().publicKey;
      const threatPda = threatPdaFor(target);
      // Authority registers, impostor tries to clear.
      await program.methods
        .registerThreat(new anchor.BN(70), { sybil: {} }, "sybil cluster")
        .accounts({
          registry: registryPda,
          threatRecord: threatPda,
          target,
          authority: authority.publicKey,
        })
        .rpc();
      try {
        await program.methods
          .clearThreat()
          .accounts({
            registry: registryPda,
            threatRecord: threatPda,
            authority: impostor.publicKey,
          })
          .signers([impostor])
          .rpc();
        expect.fail("unauthorized clear should have failed");
      } catch (err) {
        expect(String(err)).to.match(/ConstraintHasOne|wrong authority|not the authority/i);
      }
    });
  });

  describe("authority transfer", () => {
    it("rejects a transfer by a non-authority", async () => {
      try {
        await program.methods
          .transferAuthority(newAuthority.publicKey)
          .accounts({ registry: registryPda, authority: impostor.publicKey })
          .signers([impostor])
          .rpc();
        expect.fail("unauthorized transfer should have failed");
      } catch (err) {
        expect(String(err)).to.match(/ConstraintHasOne|wrong authority|not the authority/i);
      }
    });

    it("completes the two-step transfer", async () => {
      await program.methods
        .transferAuthority(newAuthority.publicKey)
        .accounts({ registry: registryPda, authority: authority.publicKey })
        .rpc();

      // The nominee must accept; the old authority cannot accept.
      await program.methods
        .acceptAuthority()
        .accounts({
          registry: registryPda,
          pendingAuthoritySigner: newAuthority.publicKey,
        })
        .signers([newAuthority])
        .rpc();

      const registry = await program.account.registry.fetch(registryPda);
      expect(registry.authority.equals(newAuthority.publicKey)).to.be.true;
      expect(registry.pendingAuthority.equals(anchor.web3.PublicKey.default)).to
        .be.true;

      // Old authority must now be rejected everywhere.
      try {
        await program.methods
          .updateRiskScore(new anchor.BN(1))
          .accounts({
            registry: registryPda,
            threatRecord: threatPdaFor(targetKey),
            authority: authority.publicKey,
          })
          .rpc();
        expect.fail("old authority should have lost power");
      } catch (err) {
        expect(String(err)).to.match(/ConstraintHasOne|wrong authority|not the authority/i);
      }
    });
  });
});
