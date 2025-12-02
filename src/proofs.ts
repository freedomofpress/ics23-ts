import { applyInner, applyLeaf, doHash } from "./ops";
import {
  ExistenceProof,
  HashOp,
  InnerOp,
  InnerSpec,
  LengthOp,
  NonExistenceProof,
  ProofSpec,
} from "./proto/cosmos/ics23/v1/proofs";
import {
  bytesEqual,
  ensureBytesBefore,
  ensureBytesEqual,
  ensureInner,
  ensureLeaf,
} from "./specs";

export const iavlSpec: ProofSpec = {
  leafSpec: {
    prefix: Uint8Array.from([0]),
    hash: HashOp.SHA256,
    prehashValue: HashOp.SHA256,
    prehashKey: HashOp.NO_HASH,
    length: LengthOp.VAR_PROTO,
  },
  innerSpec: {
    childOrder: [0, 1],
    minPrefixLength: 4,
    maxPrefixLength: 12,
    childSize: 33,
    hash: HashOp.SHA256,
    emptyChild: new Uint8Array(),
  },
  minDepth: 0,
  maxDepth: 255,
  prehashKeyBeforeComparison: false,
};

export const tendermintSpec: ProofSpec = {
  leafSpec: {
    prefix: Uint8Array.from([0]),
    hash: HashOp.SHA256,
    prehashValue: HashOp.SHA256,
    prehashKey: HashOp.NO_HASH,
    length: LengthOp.VAR_PROTO,
  },
  innerSpec: {
    childOrder: [0, 1],
    minPrefixLength: 1,
    maxPrefixLength: 1,
    childSize: 32,
    hash: HashOp.SHA256,
    emptyChild: new Uint8Array(),
  },
  minDepth: 0,
  maxDepth: 255,
  prehashKeyBeforeComparison: false,
};

export const smtSpec: ProofSpec = {
  leafSpec: {
    hash: HashOp.SHA256,
    prehashKey: HashOp.SHA256,
    prehashValue: HashOp.SHA256,
    length: LengthOp.NO_PREFIX,
    prefix: Uint8Array.from([0]),
  },
  innerSpec: {
    childOrder: [0, 1],
    childSize: 32,
    minPrefixLength: 1,
    maxPrefixLength: 1,
    emptyChild: new Uint8Array(32),
    hash: HashOp.SHA256,
  },
  maxDepth: 256,
  minDepth: 0,
  prehashKeyBeforeComparison: true,
};

export type CommitmentRoot = Uint8Array;

export async function keyForComparison(
  spec: ProofSpec,
  key: Uint8Array,
): Promise<Uint8Array> {
  if (!spec.prehashKeyBeforeComparison) {
    return key;
  }

  return doHash(spec.leafSpec!.prehashKey!, key);
}

// verifyExistence will throw an error if the proof doesn't link key, value -> root
// or if it doesn't fulfill the spec
export async function verifyExistence(
  proof: ExistenceProof,
  spec: ProofSpec,
  root: CommitmentRoot,
  key: Uint8Array,
  value: Uint8Array,
): Promise<void> {
  ensureSpec(proof, spec);
  const calc = await calculateExistenceRoot(proof);
  ensureBytesEqual(calc, root);
  ensureBytesEqual(key, proof.key!);
  ensureBytesEqual(value, proof.value!);
}

// Verify does all checks to ensure the proof has valid non-existence proofs,
// and they ensure the given key is not in the CommitmentState,
// throwing an error if there is an issue
export async function verifyNonExistence(
  proof: NonExistenceProof,
  spec: ProofSpec,
  root: CommitmentRoot,
  key: Uint8Array,
): Promise<void> {
  let leftKey: Uint8Array | undefined;
  let rightKey: Uint8Array | undefined;

  if (proof.left) {
    await verifyExistence(
      proof.left,
      spec,
      root,
      proof.left.key!,
      proof.left.value!,
    );
    leftKey = proof.left.key!;
  }
  if (proof.right) {
    await verifyExistence(
      proof.right,
      spec,
      root,
      proof.right.key!,
      proof.right.value!,
    );
    rightKey = proof.right.key!;
  }

  if (!leftKey && !rightKey) {
    throw new Error("neither left nor right proof defined");
  }

  if (leftKey) {
    ensureBytesBefore(
      await keyForComparison(spec, leftKey),
      await keyForComparison(spec, key),
    );
  }
  if (rightKey) {
    ensureBytesBefore(
      await keyForComparison(spec, key),
      await keyForComparison(spec, rightKey),
    );
  }

  if (!spec.innerSpec) {
    throw new Error("no inner spec");
  }
  if (!leftKey) {
    ensureLeftMost(spec.innerSpec, proof.right!.path!);
  } else if (!rightKey) {
    ensureRightMost(spec.innerSpec, proof.left!.path!);
  } else {
    ensureLeftNeighbor(spec.innerSpec, proof.left!.path!, proof.right!.path!);
  }
  return;
}

// Calculate determines the root hash that matches the given proof.
// You must validate the result is what you have in a header.
// Returns error if the calculations cannot be performed.
export async function calculateExistenceRoot(
  proof: ExistenceProof,
): Promise<CommitmentRoot> {
  if (!proof.key || !proof.value) {
    throw new Error("Existence proof needs key and value set");
  }
  if (!proof.leaf) {
    throw new Error("Existence proof must start with a leaf operation");
  }
  const path = proof.path || [];

  let res = await applyLeaf(proof.leaf, proof.key, proof.value);
  for (const inner of path) {
    res = await applyInner(inner, res);
  }
  return res;
}

// ensureSpec throws an Error if proof doesn't fulfill spec
export function ensureSpec(proof: ExistenceProof, spec: ProofSpec): void {
  if (!proof.leaf) {
    throw new Error("Existence proof must start with a leaf operation");
  }
  if (!spec.leafSpec) {
    throw new Error("Spec must include leafSpec");
  }
  if (!spec.innerSpec) {
    throw new Error("Spec must include innerSpec");
  }
  ensureLeaf(proof.leaf, spec.leafSpec);

  const path = proof.path || [];
  if (spec.minDepth && path.length < spec.minDepth) {
    throw new Error(`Too few inner nodes ${path.length}`);
  }
  if (spec.maxDepth && path.length > spec.maxDepth) {
    throw new Error(`Too many inner nodes ${path.length}`);
  }
  for (const inner of path) {
    ensureInner(inner, spec.leafSpec.prefix, spec.innerSpec);
  }
}

function ensureLeftMost(spec: InnerSpec, path: readonly InnerOp[]): void {
  const { minPrefix, maxPrefix, suffix } = getPadding(spec, 0);

  // ensure every step has a prefix and suffix defined to be leftmost
  for (const step of path) {
    if (!hasPadding(step, minPrefix, maxPrefix, suffix)) {
      throw new Error("Step not leftmost");
    }
  }
}

function ensureRightMost(spec: InnerSpec, path: readonly InnerOp[]): void {
  const len = spec.childOrder!.length - 1;
  const { minPrefix, maxPrefix, suffix } = getPadding(spec, len);

  // ensure every step has a prefix and suffix defined to be leftmost
  for (const step of path) {
    if (!hasPadding(step, minPrefix, maxPrefix, suffix)) {
      throw new Error("Step not leftmost");
    }
  }
}

export function ensureLeftNeighbor(
  spec: InnerSpec,
  left: readonly InnerOp[],
  right: readonly InnerOp[],
): void {
  const mutleft: InnerOp[] = [...left];
  const mutright: InnerOp[] = [...right];

  let topleft = mutleft.pop()!;
  let topright = mutright.pop()!;
  while (
    bytesEqual(topleft.prefix!, topright.prefix!) &&
    bytesEqual(topleft.suffix!, topright.suffix!)
  ) {
    topleft = mutleft.pop()!;
    topright = mutright.pop()!;
  }

  // now topleft and topright are the first divergent nodes
  // make sure they are left and right of each other
  if (!isLeftStep(spec, topleft, topright)) {
    throw new Error(`Not left neightbor at first divergent step`);
  }

  // make sure the paths are left and right most possibilities respectively
  ensureRightMost(spec, mutleft);
  ensureLeftMost(spec, mutright);
}

// isLeftStep assumes left and right have common parents
// checks if left is exactly one slot to the left of right
function isLeftStep(spec: InnerSpec, left: InnerOp, right: InnerOp): boolean {
  const leftidx = orderFromPadding(spec, left);
  const rightidx = orderFromPadding(spec, right);
  return rightidx === leftidx + 1;
}

function orderFromPadding(spec: InnerSpec, inner: InnerOp): number {
  for (let branch = 0; branch < spec.childOrder!.length; branch++) {
    const { minPrefix, maxPrefix, suffix } = getPadding(spec, branch);
    if (hasPadding(inner, minPrefix, maxPrefix, suffix)) {
      return branch;
    }
  }
  throw new Error(`Cannot find any valid spacing for this node`);
}

function hasPadding(
  op: InnerOp,
  minPrefix: number,
  maxPrefix: number,
  suffix: number,
): boolean {
  if ((op.prefix || []).length < minPrefix) {
    return false;
  }
  if ((op.prefix || []).length > maxPrefix) {
    return false;
  }
  return (op.suffix || []).length === suffix;
}

interface PaddingResult {
  readonly minPrefix: number;
  readonly maxPrefix: number;
  readonly suffix: number;
}
function getPadding(spec: InnerSpec, branch: number): PaddingResult {
  const idx = getPosition(spec.childOrder!, branch);

  // count how many children are in the prefix
  const prefix = idx * spec.childSize!;
  const minPrefix = prefix + spec.minPrefixLength!;
  const maxPrefix = prefix + spec.maxPrefixLength!;

  // count how many children are in the suffix
  const suffix = (spec.childOrder!.length - 1 - idx) * spec.childSize!;
  return { minPrefix, maxPrefix, suffix };
}

function getPosition(order: readonly number[], branch: number): number {
  if (branch < 0 || branch >= order.length) {
    throw new Error(`Invalid branch: ${branch}`);
  }
  return order.findIndex((val) => val === branch);
}
