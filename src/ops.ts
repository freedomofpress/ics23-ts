import {
  HashOp,
  InnerOp,
  LeafOp,
  LengthOp,
} from "./proto/cosmos/ics23/v1/proofs";

const subtle = globalThis.crypto?.subtle;

async function sha256(preimage: Uint8Array): Promise<Uint8Array> {
  if (!subtle) {
    throw new Error("Web Crypto API is not available");
  }

  const digest = await subtle.digest("SHA-256", preimage);
  return new Uint8Array(digest);
}

export async function applyLeaf(
  leaf: LeafOp,
  key: Uint8Array,
  value: Uint8Array,
): Promise<Uint8Array> {
  if (key.length === 0) {
    throw new Error("Missing key");
  }
  if (value.length === 0) {
    throw new Error("Missing value");
  }
  const pkey = await prepareLeafData(
    ensureHash(leaf.prehashKey),
    ensureLength(leaf.length),
    key,
  );
  const pvalue = await prepareLeafData(
    ensureHash(leaf.prehashValue),
    ensureLength(leaf.length),
    value,
  );
  const data = new Uint8Array([
    ...ensureBytes(leaf.prefix),
    ...pkey,
    ...pvalue,
  ]);
  return doHash(ensureHash(leaf.hash), data);
}

export async function applyInner(
  inner: InnerOp,
  child: Uint8Array,
): Promise<Uint8Array> {
  if (child.length === 0) {
    throw new Error("Inner op needs child value");
  }
  const preimage = new Uint8Array([
    ...ensureBytes(inner.prefix),
    ...child,
    ...ensureBytes(inner.suffix),
  ]);
  return doHash(ensureHash(inner.hash), preimage);
}

function ensure<T>(maybe: T | undefined | null, value: T): T {
  return maybe === undefined || maybe === null ? value : maybe;
}

const ensureHash = (h: HashOp | null | undefined): HashOp =>
  ensure(h, HashOp.NO_HASH);
const ensureLength = (l: LengthOp | null | undefined): LengthOp =>
  ensure(l, LengthOp.NO_PREFIX);
const ensureBytes = (b: Uint8Array | null | undefined): Uint8Array =>
  ensure(b, new Uint8Array([]));

async function prepareLeafData(
  hashOp: HashOp,
  lengthOp: LengthOp,
  data: Uint8Array,
): Promise<Uint8Array> {
  const h = await doHashOrNoop(hashOp, data);
  return doLengthOp(lengthOp, h);
}

// doHashOrNoop will return the preimage untouched if hashOp == NONE,
// otherwise, perform doHash
async function doHashOrNoop(
  hashOp: HashOp,
  preimage: Uint8Array,
): Promise<Uint8Array> {
  if (hashOp === HashOp.NO_HASH) {
    return preimage;
  }
  return doHash(hashOp, preimage);
}

// doHash will perform the specified hash on the preimage.
// if hashOp == NONE, it will return an error (use doHashOrNoop if you want different behavior)
export async function doHash(
  hashOp: HashOp,
  preimage: Uint8Array,
): Promise<Uint8Array> {
  if (hashOp === HashOp.SHA256) {
    return sha256(preimage);
  }

  throw new Error(`Unsupported hashop: ${hashOp}`);
}

// doLengthOp will calculate the proper prefix and return it prepended
//   doLengthOp(op, data) -> length(data) || data
function doLengthOp(lengthOp: LengthOp, data: Uint8Array): Uint8Array {
  switch (lengthOp) {
    case LengthOp.NO_PREFIX:
      return data;
    case LengthOp.VAR_PROTO:
      return new Uint8Array([...encodeVarintProto(data.length), ...data]);
    case LengthOp.REQUIRE_32_BYTES:
      if (data.length !== 32) {
        throw new Error(`Length is ${data.length}, not 32 bytes`);
      }
      return data;
    case LengthOp.REQUIRE_64_BYTES:
      if (data.length !== 64) {
        throw new Error(`Length is ${data.length}, not 64 bytes`);
      }
      return data;
    case LengthOp.FIXED32_LITTLE:
      return new Uint8Array([...encodeFixed32Le(data.length), ...data]);
    // TODO
    // case LengthOp_VAR_RLP:
    // case LengthOp_FIXED32_BIG:
    // case LengthOp_FIXED64_BIG:
    // case LengthOp_FIXED64_LITTLE:
  }
  throw new Error(`Unsupported lengthop: ${lengthOp}`);
}

function encodeVarintProto(n: number): Uint8Array {
  let enc: readonly number[] = [];
  let l = n;
  while (l >= 128) {
    const b = (l % 128) + 128;
    enc = [...enc, b];
    l = l / 128;
  }
  enc = [...enc, l];
  return new Uint8Array(enc);
}

function encodeFixed32Le(n: number): Uint8Array {
  const enc = new Uint8Array(4);
  let l = n;
  for (let i = enc.length; i > 0; i--) {
    enc[Math.abs(i - enc.length)] = l % 256;
    l = Math.floor(l / 256);
  }
  return enc;
}
