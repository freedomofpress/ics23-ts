import { doHash } from "./ops";
import { verifyExistence } from "./proofs";
import {
  CommitmentProof,
  HashOp,
  LengthOp,
  ProofSpec,
} from "./proto/cosmos/ics23/v1/proofs";
import { bytesEqual } from "./specs";

export type WebcatLeaf = readonly [string, string];

export interface WebcatLeavesFile {
  readonly block_height: number;
  readonly leaves: readonly (WebcatLeaf | readonly string[])[];
  readonly proof: {
    readonly app_hash: string;
    readonly canonical_root_hash: string;
    readonly merkle_proof: {
      readonly proof_bytes: readonly string[];
    };
  };
}

function fromHex(hexstring: string): Uint8Array {
  if (hexstring.length % 2 !== 0) {
    throw new Error("hex string length must be a multiple of 2");
  }

  const listOfInts: number[] = [];
  for (let i = 0; i < hexstring.length; i += 2) {
    const hexByteAsString = hexstring.substr(i, 2);
    if (!hexByteAsString.match(/[0-9a-f]{2}/i)) {
      throw new Error("hex string contains invalid characters");
    }
    listOfInts.push(parseInt(hexByteAsString, 16));
  }
  return new Uint8Array(listOfInts);
}

const utf8Encoder = new TextEncoder();

const leafPrefix = utf8Encoder.encode("JMT::LeafNode");
const innerPrefix = utf8Encoder.encode("JMT::IntrnalNode");
const placeholderMarker =
  "SPARSE_MERKLE_PLACEHOLDER_HASH__" satisfies string;

export const webcatSpec: ProofSpec = {
  leafSpec: {
    hash: HashOp.SHA256,
    prehashKey: HashOp.SHA256,
    prehashValue: HashOp.SHA256,
    length: LengthOp.NO_PREFIX,
    prefix: leafPrefix,
  },
  innerSpec: {
    hash: HashOp.SHA256,
    childOrder: [0, 1],
    childSize: 32,
    minPrefixLength: innerPrefix.length,
    maxPrefixLength: innerPrefix.length,
    emptyChild: new Uint8Array(),
  },
  maxDepth: 256,
  minDepth: 0,
  prehashKeyBeforeComparison: true,
};

function decodeProof(hex: string): CommitmentProof {
  return CommitmentProof.decode(fromHex(hex));
}

async function hashUtf8(message: string): Promise<Uint8Array> {
  return doHash(HashOp.SHA256, utf8Encoder.encode(message));
}

async function placeholderHash(): Promise<Uint8Array> {
  return hashUtf8(placeholderMarker);
}

function canonicalizeKey(key: string): string {
  return key.replace(/^canonical\//, "");
}

function normalizeLeaf(leaf: WebcatLeaf | readonly string[]): WebcatLeaf {
  if (leaf.length < 2) {
    throw new Error("Leaf entry must contain a key and value");
  }

  return [leaf[0], leaf[1]];
}

async function leafHash(key: string, valueHex: string): Promise<Uint8Array> {
  const hashedKey = await doHash(
    HashOp.SHA256,
    utf8Encoder.encode(canonicalizeKey(key)),
  );
  const hashedValue = await doHash(HashOp.SHA256, fromHex(valueHex));
  const preimage = new Uint8Array([
    ...leafPrefix,
    ...hashedKey,
    ...hashedValue,
  ]);
  return doHash(HashOp.SHA256, preimage);
}

async function combineChildren(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  const preimage = new Uint8Array([...innerPrefix, ...left, ...right]);
  return doHash(HashOp.SHA256, preimage);
}

interface PreparedLeaf {
  readonly keyHash: Uint8Array;
  readonly nodeHash: Uint8Array;
}

function bitIsSet(hash: Uint8Array, depth: number): boolean {
  const byteIndex = Math.floor(depth / 8);
  const bitIndex = 7 - (depth % 8);
  const byte = hash[byteIndex] ?? 0;
  return ((byte >> bitIndex) & 1) === 1;
}

async function prepareLeaves(
  leaves: readonly WebcatLeaf[],
): Promise<PreparedLeaf[]> {
  const prepared: PreparedLeaf[] = [];
  for (const [key, valueHex] of leaves) {
    const keyHash = await doHash(
      HashOp.SHA256,
      utf8Encoder.encode(canonicalizeKey(key)),
    );
    const nodeHash = await leafHash(key, valueHex);
    prepared.push({ keyHash, nodeHash });
  }
  return prepared;
}

async function buildJmtRoot(
  placeholder: Uint8Array,
  leaves: readonly PreparedLeaf[],
  depth = 0,
): Promise<Uint8Array> {
  if (leaves.length === 0) {
    return placeholder;
  }

  if (leaves.length === 1 || depth >= 256) {
    return leaves[0]!.nodeHash;
  }

  const left: PreparedLeaf[] = [];
  const right: PreparedLeaf[] = [];

  for (const leaf of leaves) {
    (bitIsSet(leaf.keyHash, depth) ? right : left).push(leaf);
  }

  const leftHash = left.length
    ? await buildJmtRoot(placeholder, left, depth + 1)
    : placeholder;
  const rightHash = right.length
    ? await buildJmtRoot(placeholder, right, depth + 1)
    : placeholder;

  return combineChildren(leftHash, rightHash);
}

async function reconstructCanonicalRoot(
  leaves: readonly (WebcatLeaf | readonly string[])[],
): Promise<Uint8Array> {
  const placeholder = await placeholderHash();
  if (leaves.length === 0) {
    return placeholder;
  }

  const prepared = await prepareLeaves(leaves.map(normalizeLeaf));
  return buildJmtRoot(placeholder, prepared);
}

async function verifyCanonicalRootLink(
  appHashHex: string,
  canonicalRootHex: string,
  proofBytes: readonly string[],
): Promise<boolean> {
  if (proofBytes.length === 0) {
    return false;
  }

  const canonicalProof = decodeProof(proofBytes[proofBytes.length - 1]);
  if (!canonicalProof.exist) {
    return false;
  }

  await verifyExistence(
    canonicalProof.exist,
    webcatSpec,
    fromHex(appHashHex),
    utf8Encoder.encode("canonical"),
    fromHex(canonicalRootHex),
  );

  return true;
}

export async function verifyWebcatProof(
  data: WebcatLeavesFile,
): Promise<readonly WebcatLeaf[] | false> {
  try {
    const normalizedLeaves = data.leaves.map(normalizeLeaf);

    const reconstructedRoot = await reconstructCanonicalRoot(normalizedLeaves);
    if (
      !bytesEqual(reconstructedRoot, fromHex(data.proof.canonical_root_hash))
    ) {
      return false;
    }

    const canonicalLinkValid = await verifyCanonicalRootLink(
      data.proof.app_hash,
      data.proof.canonical_root_hash,
      data.proof.merkle_proof.proof_bytes,
    );

    if (!canonicalLinkValid) {
      return false;
    }

    return normalizedLeaves;
  } catch {
    return false;
  }
}
