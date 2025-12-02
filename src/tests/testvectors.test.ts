import iavlExistLeft from "../../testdata/iavl/exist_left.json";
import iavlExistMiddle from "../../testdata/iavl/exist_middle.json";
import iavlExistRight from "../../testdata/iavl/exist_right.json";
import iavlNonexistLeft from "../../testdata/iavl/nonexist_left.json";
import iavlNonexistMiddle from "../../testdata/iavl/nonexist_middle.json";
import iavlNonexistRight from "../../testdata/iavl/nonexist_right.json";
import smtExistLeft from "../../testdata/smt/exist_left.json";
import smtExistMiddle from "../../testdata/smt/exist_middle.json";
import smtExistRight from "../../testdata/smt/exist_right.json";
import smtNonexistLeft from "../../testdata/smt/nonexist_left.json";
import smtNonexistMiddle from "../../testdata/smt/nonexist_middle.json";
import smtNonexistRight from "../../testdata/smt/nonexist_right.json";
import tendermintExistLeft from "../../testdata/tendermint/exist_left.json";
import tendermintExistMiddle from "../../testdata/tendermint/exist_middle.json";
import tendermintExistRight from "../../testdata/tendermint/exist_right.json";
import tendermintNonexistLeft from "../../testdata/tendermint/nonexist_left.json";
import tendermintNonexistMiddle from "../../testdata/tendermint/nonexist_middle.json";
import tendermintNonexistRight from "../../testdata/tendermint/nonexist_right.json";

import { compress } from "./../compress";
import {
  batchVerifyMembership,
  batchVerifyNonMembership,
  verifyMembership,
  verifyNonMembership,
} from "./../ics23";
import { iavlSpec, smtSpec, tendermintSpec } from "./../proofs";
import { fromHex } from "./testhelpers";

import { describe, it, expect } from "vitest";
import {
  BatchEntry,
  CommitmentProof,
  ProofSpec,
} from "./../proto/cosmos/ics23/v1/proofs";

describe("calculateExistenceRoot", () => {
  interface RefData {
    readonly root: Uint8Array;
    readonly key: Uint8Array;
    readonly value?: Uint8Array;
  }

  interface TestVectorJson {
    readonly root: string;
    readonly proof: string;
    readonly key: string;
    readonly value?: string;
  }

  interface LoadResult {
    readonly proof: CommitmentProof;
    readonly data: RefData;
  }

  function loadVector(vector: TestVectorJson): LoadResult {
    const { root, proof, key, value } = vector;
    expect(proof).toBeDefined();
    expect(root).toBeDefined();
    expect(key).toBeDefined();

    const commit = CommitmentProof.decode(fromHex(proof));

    const data = {
      root: fromHex(root),
      key: fromHex(key),
      value: value ? fromHex(value) : undefined,
    };

    return { proof: commit, data };
  }

  interface BatchResult {
    readonly proof: CommitmentProof;
    readonly data: readonly RefData[];
  }

  async function validateTestVector(
    vector: TestVectorJson,
    spec: ProofSpec,
  ): Promise<void> {
    const {
      proof,
      data: { root, key, value },
    } = loadVector(vector);
    if (value) {
      const valid = await verifyMembership(proof, spec, root, key, value);
      expect(valid).toBe(true);
    } else {
      const valid = await verifyNonMembership(proof, spec, root, key);
      expect(valid).toBe(true);
    }
  }

  it("should parse iavl left", async () => {
    await validateTestVector(iavlExistLeft, iavlSpec);
  });
  it("should parse iavl right", async () => {
    await validateTestVector(iavlExistRight, iavlSpec);
  });
  it("should parse iavl middle", async () => {
    await validateTestVector(iavlExistMiddle, iavlSpec);
  });
  it("should parse iavl left - nonexist", async () => {
    await validateTestVector(iavlNonexistLeft, iavlSpec);
  });
  it("should parse iavl right - nonexist", async () => {
    await validateTestVector(iavlNonexistRight, iavlSpec);
  });
  it("should parse iavl middle - nonexist", async () => {
    await validateTestVector(iavlNonexistMiddle, iavlSpec);
  });

  it("should parse tendermint left", async () => {
    await validateTestVector(tendermintExistLeft, tendermintSpec);
  });
  it("should parse tendermint right", async () => {
    await validateTestVector(tendermintExistRight, tendermintSpec);
  });
  it("should parse tendermint middle", async () => {
    await validateTestVector(tendermintExistMiddle, tendermintSpec);
  });
  it("should parse tendermint left - nonexist", async () => {
    await validateTestVector(tendermintNonexistLeft, tendermintSpec);
  });
  it("should parse tendermint right - nonexist", async () => {
    await validateTestVector(tendermintNonexistRight, tendermintSpec);
  });
  it("should parse tendermint middle - nonexist", async () => {
    await validateTestVector(tendermintNonexistMiddle, tendermintSpec);
  });

  function loadBatch(vectors: readonly TestVectorJson[]): BatchResult {
    let refs: readonly RefData[] = [];
    let entries: readonly BatchEntry[] = [];

    for (const vector of vectors) {
      const { proof, data } = loadVector(vector);
      refs = [...refs, data];
      if (proof.exist) {
        entries = [...entries, { exist: proof.exist }];
      } else if (proof.nonexist) {
        entries = [...entries, { nonexist: proof.nonexist }];
      }
    }
    const commit: CommitmentProof = {
      batch: {
        entries: entries as BatchEntry[],
      },
    };

    return {
      proof: commit,
      data: refs,
    };
  }

  async function validateBatch(
    proof: CommitmentProof,
    spec: ProofSpec,
    data: RefData,
  ): Promise<void> {
    const { root, key, value } = data;
    if (value) {
      let valid = await verifyMembership(proof, spec, root, key, value);
      expect(valid).toBe(true);
      const items = new Map([[key, value]]);
      valid = await batchVerifyMembership(proof, spec, root, items);
      expect(valid).toBe(true);
    } else {
      let valid = await verifyNonMembership(proof, spec, root, key);
      expect(valid).toBe(true);
      const keys: readonly Uint8Array[] = [key];
      valid = await batchVerifyNonMembership(proof, spec, root, keys);
      expect(valid).toBe(true);
    }
  }

  it("should validate iavl batch exist", async () => {
    const { proof, data } = loadBatch([
      iavlExistLeft,
      iavlExistRight,
      iavlExistMiddle,
      iavlNonexistLeft,
      iavlNonexistRight,
      iavlNonexistMiddle,
    ]);
    await validateBatch(proof, iavlSpec, data[0]);
  });

  it("should validate iavl batch nonexist", async () => {
    const { proof, data } = loadBatch([
      iavlExistLeft,
      iavlExistRight,
      iavlExistMiddle,
      iavlNonexistLeft,
      iavlNonexistRight,
      iavlNonexistMiddle,
    ]);
    await validateBatch(proof, iavlSpec, data[5]);
  });

  it("should validate compressed iavl batch exist", async () => {
    const { proof, data } = loadBatch([
      iavlExistLeft,
      iavlExistRight,
      iavlExistMiddle,
      iavlNonexistLeft,
      iavlNonexistRight,
      iavlNonexistMiddle,
    ]);
    const small = compress(proof);

    // ensure this is actually a different format
    const origBin = CommitmentProof.encode(proof).finish();
    const origBin2 = CommitmentProof.encode(proof).finish();
    const smallBin = CommitmentProof.encode(small).finish();
    expect(origBin).toEqual(origBin2);
    expect(origBin).not.toEqual(smallBin);

    await validateBatch(small, iavlSpec, data[0]);
  });

  it("should validate compressed iavl batch nonexist", async () => {
    const { proof, data } = loadBatch([
      iavlExistLeft,
      iavlExistRight,
      iavlExistMiddle,
      iavlNonexistLeft,
      iavlNonexistRight,
      iavlNonexistMiddle,
    ]);
    const small = compress(proof);

    // ensure this is actually a different format
    const origBin = CommitmentProof.encode(proof).finish();
    const origBin2 = CommitmentProof.encode(proof).finish();
    const smallBin = CommitmentProof.encode(small).finish();
    expect(origBin).toEqual(origBin2);
    expect(origBin).not.toEqual(smallBin);

    await validateBatch(small, iavlSpec, data[5]);
  });

  it("should validate tendermint batch exist", async () => {
    const { proof, data } = loadBatch([
      tendermintExistLeft,
      tendermintExistRight,
      tendermintExistMiddle,
      tendermintNonexistLeft,
      tendermintNonexistRight,
      tendermintNonexistMiddle,
    ]);
    await validateBatch(proof, tendermintSpec, data[2]);
  });

  it("should validate tendermint batch nonexist", async () => {
    const { proof, data } = loadBatch([
      tendermintExistLeft,
      tendermintExistRight,
      tendermintExistMiddle,
      tendermintNonexistLeft,
      tendermintNonexistRight,
      tendermintNonexistMiddle,
    ]);
    await validateBatch(proof, tendermintSpec, data[3]);
  });

  it("should validate smt batch exist", async () => {
    const { proof, data } = loadBatch([
      smtExistLeft,
      smtExistRight,
      smtExistMiddle,
      smtNonexistLeft,
      smtNonexistRight,
      smtNonexistMiddle,
    ]);
    await validateBatch(proof, smtSpec, data[2]);
  });

  it("should validate smt batch nonexist", async () => {
    const { proof, data } = loadBatch([
      smtExistLeft,
      smtExistRight,
      smtExistMiddle,
      smtNonexistLeft,
      smtNonexistRight,
      smtNonexistMiddle,
    ]);
    await validateBatch(proof, smtSpec, data[3]);
  });
});
