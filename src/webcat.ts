import { verifyExistence } from "./proofs";
import {
  CommitmentProof,
  HashOp,
  LengthOp,
  ProofSpec,
} from "./proto/cosmos/ics23/v1/proofs";

export interface WebcatLeavesFile {
  readonly block_height: number;
  readonly leaves: readonly (readonly [string, string] | readonly string[])[];
  readonly proof: {
    readonly app_hash: string;
    readonly canonical_root_hash: string;
    readonly merkle_proof: {
      readonly proof_bytes: readonly string[];
      readonly representative_key: string;
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
const innerPrefix = utf8Encoder.encode("JMT::InternalNode");

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
    minPrefixLength: innerPrefix.length - 1,
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

function collectLeafValue(
  data: WebcatLeavesFile,
  representativeKey: string,
): Uint8Array {
  const match = data.leaves.find(([key]) => key === representativeKey);
  if (!match) {
    throw new Error("Representative key is missing from leaf set");
  }
  return fromHex(match[1]);
}

function stripCanonicalPrefix(key: string): string {
  return key.replace(/^canonical\//, "");
}

export async function verifyWebcatProof(
  data: WebcatLeavesFile,
): Promise<boolean> {
  try {
    const { proof_bytes: proofBytes, representative_key } =
      data.proof.merkle_proof;
    if (proofBytes.length < 2) {
      return false;
    }

    const elementProof = decodeProof(proofBytes[0]);
    const canonicalProof = decodeProof(proofBytes[1]);

    const canonicalRoot = fromHex(data.proof.canonical_root_hash);
    const appHash = fromHex(data.proof.app_hash);

    const elementKey = utf8Encoder.encode(
      stripCanonicalPrefix(representative_key),
    );
    const elementValue = collectLeafValue(data, representative_key);

    if (!elementProof.exist || !canonicalProof.exist) {
      return false;
    }

    await verifyExistence(
      elementProof.exist,
      webcatSpec,
      canonicalRoot,
      elementKey,
      elementValue,
    );

    const canonicalKey = utf8Encoder.encode("canonical");
    await verifyExistence(
      canonicalProof.exist,
      webcatSpec,
      appHash,
      canonicalKey,
      canonicalRoot,
    );

    return true;
  } catch {
    return false;
  }
}
