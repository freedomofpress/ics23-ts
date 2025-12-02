import leavesData from "../../testdata/webcat/leaves.json";

import { describe, expect, it } from "vitest";

import { calculateExistenceRoot, verifyExistence } from "../proofs";
import { verifyWebcatProof, webcatSpec } from "../webcat";
import { CommitmentProof } from "../proto/cosmos/ics23/v1/proofs";
import { fromHex, toHex } from "./testhelpers";

describe("verifyWebcatProof", () => {
  it("verifies the provided leaf and canonical linkage", async () => {
    const [elementBytes, canonicalBytes] =
      leavesData.proof.merkle_proof.proof_bytes;
    const elementProof = CommitmentProof.decode(fromHex(elementBytes));
    const canonicalProof = CommitmentProof.decode(fromHex(canonicalBytes));
    const elementRoot = await calculateExistenceRoot(elementProof.exist!);
    const canonicalRoot = await calculateExistenceRoot(canonicalProof.exist!);
    const elementKey = new TextEncoder().encode(
      leavesData.proof.merkle_proof.representative_key.replace(
        /^canonical\//,
        "",
      ),
    );

    const elementValue = fromHex(leavesData.leaves[1][1]);

    expect(elementProof.exist?.key).toEqual(elementKey);
    await expect(
      verifyExistence(
        elementProof.exist!,
        webcatSpec,
        fromHex(leavesData.proof.canonical_root_hash),
        elementKey,
        elementValue,
      ),
    ).resolves.not.toThrow();
    await expect(
      verifyExistence(
        canonicalProof.exist!,
        webcatSpec,
        fromHex(leavesData.proof.app_hash),
        new TextEncoder().encode("canonical"),
        fromHex(leavesData.proof.canonical_root_hash),
      ),
    ).resolves.not.toThrow();

    expect(toHex(elementRoot)).toBe(leavesData.proof.canonical_root_hash);
    expect(toHex(canonicalRoot)).toBe(leavesData.proof.app_hash);
    await expect(verifyWebcatProof(leavesData)).resolves.toBe(true);
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

  it("exposes the webcat spec for manual validation", async () => {
    const proofBytes = leavesData.proof.merkle_proof.proof_bytes[0];
    const proof = CommitmentProof.decode(fromHex(proofBytes));

    const validation = await verifyWebcatProof({
      ...leavesData,
      proof: leavesData.proof,
    });
    expect(validation).toBe(true);
    expect(webcatSpec.leafSpec?.prefix?.length).toBe(13);
    expect(proof.exist?.leaf?.prefix).toEqual(webcatSpec.leafSpec?.prefix);
  });
});
