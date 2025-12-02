import { calculateExistenceRoot, ensureSpec, iavlSpec } from "./../proofs";
import { fromHex, toAscii } from "./testhelpers";
import {
  HashOp,
  LengthOp,
  ExistenceProof,
  LeafOp,
  InnerOp,
  ProofSpec,
} from "./../proto/cosmos/ics23/v1/proofs";
import { describe, it, expect } from "vitest";

const leaf = (overrides: Partial<LeafOp>): LeafOp => ({
  hash: HashOp.NO_HASH,
  prehashKey: HashOp.NO_HASH,
  prehashValue: HashOp.NO_HASH,
  length: LengthOp.NO_PREFIX,
  prefix: new Uint8Array(),
  ...overrides,
});

const inner = (overrides: Partial<InnerOp>): InnerOp => ({
  hash: HashOp.NO_HASH,
  prefix: new Uint8Array(),
  suffix: new Uint8Array(),
  ...overrides,
});

describe("calculateExistenceRoot", () => {
  it("must have at least one step", async () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      path: [],
    };
    await expect(calculateExistenceRoot(proof)).rejects.toThrow();
  });
  it("executes one leaf step", async () => {
    const proof: ExistenceProof = {
      key: toAscii("food"),
      value: toAscii("some longer text"),
      leaf: leaf({
        hash: HashOp.SHA256,
        length: LengthOp.VAR_PROTO,
      }),
      path: [],
    };
    const expected = fromHex(
      "b68f5d298e915ae1753dd333da1f9cf605411a5f2e12516be6758f365e6db265",
    );
    await expect(calculateExistenceRoot(proof)).resolves.toEqual(expected);
  });
  it("cannot execute inner first", async () => {
    const proof: ExistenceProof = {
      key: toAscii("food"),
      value: toAscii("some longer text"),
      leaf: undefined,
      path: [
        inner({
          hash: HashOp.SHA256,
          prefix: fromHex("deadbeef00cafe00"),
        }),
      ],
    };
    await expect(calculateExistenceRoot(proof)).rejects.toThrow();
  });
  it("can execute leaf then inner", async () => {
    const proof: ExistenceProof = {
      key: toAscii("food"),
      value: toAscii("some longer text"),
      leaf: leaf({
        hash: HashOp.SHA256,
        length: LengthOp.VAR_PROTO,
      }),
      // output: b68f5d298e915ae1753dd333da1f9cf605411a5f2e12516be6758f365e6db265
      path: [
        inner({
          hash: HashOp.SHA256,
          prefix: fromHex("deadbeef00cafe00"),
        }),
        // echo -n deadbeef00cafe00b68f5d298e915ae1753dd333da1f9cf605411a5f2e12516be6758f365e6db265 | xxd -r -p | sha256sum
      ],
    };
    const expected = fromHex(
      "836ea236a6902a665c2a004c920364f24cad52ded20b1e4f22c3179bfe25b2a9",
    );
    await expect(calculateExistenceRoot(proof)).resolves.toEqual(expected);
  });
});

describe("ensureSpec", () => {
  const validLeaf = iavlSpec.leafSpec;
  const invalidLeaf = leaf({
    prefix: Uint8Array.from([0]),
    hash: HashOp.SHA512,
    prehashValue: HashOp.NO_HASH,
    prehashKey: HashOp.NO_HASH,
    length: LengthOp.VAR_PROTO,
  });

  const validInner = inner({
    hash: HashOp.SHA256,
    prefix: fromHex("deadbeef00cafe00"),
  });
  const invalidInner = inner({
    hash: HashOp.SHA256,
    prefix: fromHex("aa"),
  });
  const invalidInnerHash = inner({
    hash: HashOp.SHA512,
    prefix: fromHex("deadbeef00cafe00"),
  });

  const depthLimitedSpec: ProofSpec = {
    ...iavlSpec,
    minDepth: 2,
    maxDepth: 4,
  };

  it("rejects empty proof", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      path: [],
    };
    expect(() => ensureSpec(proof, iavlSpec)).toThrow();
  });

  it("accepts one valid leaf", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [],
    };
    // fail if this throws (invalid spec)
    ensureSpec(proof, iavlSpec);
  });

  it("rejects invalid leaf", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: invalidLeaf,
      path: [],
    };
    expect(() => ensureSpec(proof, iavlSpec)).toThrow();
  });

  it("rejects inner without leaf", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      path: [validInner],
    };
    expect(() => ensureSpec(proof, iavlSpec)).toThrow();
  });

  it("accepts leaf with one inner", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [validInner],
    };
    // fail if this throws (invalid spec)
    ensureSpec(proof, iavlSpec);
  });

  it("rejects with invalid inner (prefix)", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [invalidInner, validInner],
    };
    expect(() => ensureSpec(proof, iavlSpec)).toThrow();
  });

  it("rejects with invalid inner (hash)", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [validInner, invalidInnerHash],
    };
    expect(() => ensureSpec(proof, iavlSpec)).toThrow();
  });

  it("accepts depth limited with proper number of nodes", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [validInner, validInner, validInner],
    };
    // fail if this throws (invalid spec)
    ensureSpec(proof, depthLimitedSpec);
  });

  it("rejects depth limited with too few nodes", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [validInner],
    };
    expect(() => ensureSpec(proof, depthLimitedSpec)).toThrow();
  });

  it("rejects depth limited with too many nodes", () => {
    const proof: ExistenceProof = {
      key: toAscii("foo"),
      value: toAscii("bar"),
      leaf: validLeaf,
      path: [validInner, validInner, validInner, validInner, validInner],
    };
    expect(() => ensureSpec(proof, depthLimitedSpec)).toThrow();
  });
});
