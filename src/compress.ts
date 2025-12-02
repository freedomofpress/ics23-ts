import {
  BatchProof,
  CommitmentProof,
  CompressedBatchEntry,
  CompressedBatchProof,
  CompressedExistenceProof,
  ExistenceProof,
  InnerOp,
} from "./proto/cosmos/ics23/v1/proofs";

export function compress(proof: CommitmentProof): CommitmentProof {
  if (!proof.batch) {
    return proof;
  }
  return { compressed: compressBatch(proof.batch) };
}

export function decompress(proof: CommitmentProof): CommitmentProof {
  if (!proof.compressed) {
    return proof;
  }
  return { batch: decompressBatch(proof.compressed) };
}

function compressBatch(proof: BatchProof): CompressedBatchProof {
  const centries: CompressedBatchEntry[] = [];
  const lookup: InnerOp[] = [];
  const registry = new Map<Uint8Array, number>();

  for (const entry of proof.entries!) {
    if (entry.exist) {
      const centry = { exist: compressExist(entry.exist, lookup, registry) };
      centries.push(centry);
    } else if (entry.nonexist) {
      const non = entry.nonexist;
      const centry = {
        nonexist: {
          key: non.key,
          left: compressExist(non.left, lookup, registry),
          right: compressExist(non.right, lookup, registry),
        },
      };
      centries.push(centry);
    } else {
      throw new Error("Unexpected batch entry during compress");
    }
  }

  return {
    entries: centries,
    lookupInners: lookup,
  };
}

function compressExist(
  exist: ExistenceProof | null | undefined,
  lookup: InnerOp[],
  registry: Map<Uint8Array, number>,
): CompressedExistenceProof | undefined {
  if (!exist) {
    return undefined;
  }

  const path = exist.path!.map((inner: InnerOp) => {
    const sig = InnerOp.encode(inner).finish();
    let idx = registry.get(sig);
    if (idx === undefined) {
      idx = lookup.length;
      lookup.push(inner);
      registry.set(sig, idx);
    }
    return idx;
  });

  return {
    key: exist.key,
    value: exist.value,
    leaf: exist.leaf,
    path,
  };
}

function decompressBatch(proof: CompressedBatchProof): BatchProof {
  const lookup = proof.lookupInners!;
  const entries = proof.entries!.map((comp: CompressedBatchEntry) => {
    if (comp.exist) {
      return { exist: decompressExist(comp.exist, lookup) };
    } else if (comp.nonexist) {
      const non = comp.nonexist;
      return {
        nonexist: {
          key: non.key,
          left: decompressExist(non.left, lookup),
          right: decompressExist(non.right, lookup),
        },
      };
    } else {
      throw new Error("Unexpected batch entry during compress");
    }
  });
  return {
    entries,
  };
}

function decompressExist(
  exist: CompressedExistenceProof | null | undefined,
  lookup: readonly InnerOp[],
): ExistenceProof | undefined {
  if (!exist) {
    return undefined;
  }
  const { key, value, leaf, path } = exist;
  const newPath = (path || []).map((idx: number) => lookup[idx]);
  return { key, value, leaf, path: newPath };
}
