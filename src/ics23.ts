import { decompress } from "./compress";
import { CommitmentRoot, verifyExistence, verifyNonExistence } from "./proofs";
import { keyForComparison } from "./proofs";
import {
  BatchEntry,
  CommitmentProof,
  ExistenceProof,
  NonExistenceProof,
  ProofSpec,
} from "./proto/cosmos/ics23/v1/proofs";
import { bytesBefore, bytesEqual } from "./specs";
/*
This implements the client side functions as specified in
https://github.com/cosmos/ics/tree/master/spec/ics-023-vector-commitments

In particular:

  // Assumes ExistenceProof
  type verifyMembership = (root: CommitmentRoot, proof: CommitmentProof, key: Key, value: Value) => boolean

  // Assumes NonExistenceProof
  type verifyNonMembership = (root: CommitmentRoot, proof: CommitmentProof, key: Key) => boolean

  // Assumes BatchProof - required ExistenceProofs may be a subset of all items proven
  type batchVerifyMembership = (root: CommitmentRoot, proof: CommitmentProof, items: Map<Key, Value>) => boolean

  // Assumes BatchProof - required NonExistenceProofs may be a subset of all items proven
  type batchVerifyNonMembership = (root: CommitmentRoot, proof: CommitmentProof, keys: Set<Key>) => boolean

We make an adjustment to accept a Spec to ensure the provided proof is in the format of the expected merkle store.
This can avoid an range of attacks on fake preimages, as we need to be careful on how to map key, value -> leaf
and determine neighbors
*/

/**
 * verifyMembership ensures proof is (contains) a valid existence proof for the given
 */
export async function verifyMembership(
  proof: CommitmentProof,
  spec: ProofSpec,
  root: CommitmentRoot,
  key: Uint8Array,
  value: Uint8Array,
): Promise<boolean> {
  const norm = decompress(proof);
  const exist = getExistForKey(norm, key);
  if (!exist) {
    return false;
  }
  try {
    await verifyExistence(exist, spec, root, key, value);
    return true;
  } catch {
    return false;
  }
}

/**
 * verifyNonMembership ensures proof is (contains) a valid non-existence proof for the given key
 */
export async function verifyNonMembership(
  proof: CommitmentProof,
  spec: ProofSpec,
  root: CommitmentRoot,
  key: Uint8Array,
): Promise<boolean> {
  const norm = decompress(proof);
  const nonexist = await getNonExistForKey(spec, norm, key);
  if (!nonexist) {
    return false;
  }
  try {
    await verifyNonExistence(nonexist, spec, root, key);
    return true;
  } catch {
    return false;
  }
}

/**
 * batchVerifyMembership ensures proof is (contains) a valid existence proof for the given
 */
export async function batchVerifyMembership(
  proof: CommitmentProof,
  spec: ProofSpec,
  root: CommitmentRoot,
  items: Map<Uint8Array, Uint8Array>,
): Promise<boolean> {
  const norm = decompress(proof);
  for (const [key, value] of items.entries()) {
    if (!(await verifyMembership(norm, spec, root, key, value))) {
      return false;
    }
  }
  return true;
}

/**
 * batchVerifyNonMembership ensures proof is (contains) a valid existence proof for the given
 */
export async function batchVerifyNonMembership(
  proof: CommitmentProof,
  spec: ProofSpec,
  root: CommitmentRoot,
  keys: readonly Uint8Array[],
): Promise<boolean> {
  const norm = decompress(proof);
  for (const key of keys) {
    if (!(await verifyNonMembership(norm, spec, root, key))) {
      return false;
    }
  }
  return true;
}

function getExistForKey(
  proof: CommitmentProof,
  key: Uint8Array,
): ExistenceProof | undefined | null {
  const match = (p: ExistenceProof | null | undefined): boolean =>
    !!p && bytesEqual(key, p.key!);
  if (match(proof.exist)) {
    return proof.exist!;
  } else if (proof.batch) {
    return proof.batch
      .entries!.map((x: BatchEntry) => x.exist || null)
      .find(match);
  }
  return undefined;
}

async function getNonExistForKey(
  spec: ProofSpec,
  proof: CommitmentProof,
  key: Uint8Array,
): Promise<NonExistenceProof | undefined | null> {
  const match = async (
    p: NonExistenceProof | null | undefined,
  ): Promise<boolean> => {
    return (
      !!p &&
      (!p.left ||
        bytesBefore(
          await keyForComparison(spec, p.left.key!),
          await keyForComparison(spec, key),
        )) &&
      (!p.right ||
        bytesBefore(
          await keyForComparison(spec, key),
          await keyForComparison(spec, p.right.key!),
        ))
    );
  };
  if (await match(proof.nonexist)) {
    return proof.nonexist!;
  } else if (proof.batch) {
    for (const entry of proof.batch.entries || []) {
      const candidate = entry.nonexist || null;
      if (await match(candidate)) {
        return candidate;
      }
    }
  }
  return undefined;
}
