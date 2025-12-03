import leavesData from "../../testdata/webcat/leaves.json";

import { describe, expect, it } from "vitest";

import { calculateExistenceRoot } from "../proofs";
import { verifyWebcatProof, webcatSpec } from "../webcat";
import { CommitmentProof } from "../proto/cosmos/ics23/v1/proofs";
import { fromHex, toHex } from "./testhelpers";

describe("verifyWebcatProof", () => {
  it("verifies canonical linkage and reconstruction", async () => {
    const canonicalBytes = leavesData.proof.merkle_proof.proof_bytes[1];
    const canonicalProof = CommitmentProof.decode(fromHex(canonicalBytes));
    const canonicalRoot = await calculateExistenceRoot(canonicalProof.exist!);

    expect(toHex(canonicalRoot)).toBe(leavesData.proof.app_hash);
    await expect(verifyWebcatProof(leavesData)).resolves.toEqual(
      leavesData.leaves,
    );
  });

  it("fails when app hash linkage is modified", async () => {
    const tampered = {
      ...leavesData,
      proof: {
        ...leavesData.proof,
        app_hash: "00" + leavesData.proof.app_hash.slice(2),
      },
    };

    await expect(verifyWebcatProof(tampered)).resolves.toBe(false);
  });

  it("fails when canonical root cannot be reconstructed", async () => {
    const tamperedLeaves = {
      ...leavesData,
      leaves: leavesData.leaves.map((leaf, index) =>
        index === 0 ? [leaf[0], "00" + leaf[1].slice(2)] : leaf,
      ) as typeof leavesData.leaves,
    };

    await expect(verifyWebcatProof(tamperedLeaves)).resolves.toBe(false);
  });

  it("exposes the webcat spec for manual validation", async () => {
    const proofBytes = leavesData.proof.merkle_proof.proof_bytes[0];
    const proof = CommitmentProof.decode(fromHex(proofBytes));

    const validation = await verifyWebcatProof({
      ...leavesData,
      proof: leavesData.proof,
    });
    expect(validation).toEqual(leavesData.leaves);
    expect(webcatSpec.leafSpec?.prefix?.length).toBe(13);
    expect(proof.exist?.leaf?.prefix).toEqual(webcatSpec.leafSpec?.prefix);
  });
});
