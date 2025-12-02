import { applyInner, applyLeaf, doHash } from "./../ops";
import { fromHex, toAscii } from "./testhelpers";
import {
  HashOp,
  LeafOp,
  LengthOp,
  InnerOp,
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

describe("doHash", () => {
  it("sha256 hashes food", async () => {
    // echo -n food | sha256sum
    const hash = await doHash(HashOp.SHA256, toAscii("food"));
    expect(hash).toEqual(
      fromHex(
        "c1f026582fe6e8cb620d0c85a72fe421ddded756662a8ec00ed4c297ad10676b",
      ),
    );
  });

  it("rejects unsupported hash operations", async () => {
    await expect(doHash(HashOp.SHA512, toAscii("food"))).rejects.toThrow();
    await expect(doHash(HashOp.RIPEMD160, toAscii("food"))).rejects.toThrow();
    await expect(doHash(HashOp.BLAKE3, toAscii("food"))).rejects.toThrow();
  });
});

describe("applyLeaf", () => {
  it("hashes foobar", async () => {
    const op = leaf({ hash: HashOp.SHA256 });
    const key = toAscii("foo");
    const value = toAscii("bar");
    // echo -n foobar | sha256sum
    const expected = fromHex(
      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
    );
    await expect(applyLeaf(op, key, value)).resolves.toEqual(expected);
  });

  it("hashes foobar (different breakpoint)", async () => {
    const op = leaf({ hash: HashOp.SHA256 });
    const key = toAscii("f");
    const value = toAscii("oobar");
    // echo -n foobar | sha256sum
    const expected = fromHex(
      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
    );
    await expect(applyLeaf(op, key, value)).resolves.toEqual(expected);
  });

  it("hashes with length prefix", async () => {
    const op = leaf({
      hash: HashOp.SHA256,
      length: LengthOp.VAR_PROTO,
    });
    // echo -n food | xxd -ps
    const key = toAscii("food"); // 04666f6f64
    const value = toAscii("some longer text"); // 10736f6d65206c6f6e6765722074657874
    // echo -n 04666f6f6410736f6d65206c6f6e6765722074657874 | xxd -r -p | sha256sum -b
    const expected = fromHex(
      "b68f5d298e915ae1753dd333da1f9cf605411a5f2e12516be6758f365e6db265",
    );
    await expect(applyLeaf(op, key, value)).resolves.toEqual(expected);
  });

  it("hashes with length prefix (fixed 32-bit little-endian encoding)", async () => {
    const op = leaf({
      hash: HashOp.SHA256,
      length: LengthOp.FIXED32_LITTLE,
    });
    // echo -n food | xxd -ps
    const key = toAscii("food"); // 04000000666f6f64
    const value = toAscii("some longer text"); // 10000000736f6d65206c6f6e6765722074657874
    // echo -n 04000000666f6f6410000000736f6d65206c6f6e6765722074657874 | xxd -r -p | sha256sum
    const expected = fromHex(
      "c853652437be02501c674744bf2a2b45d92a0a9f29c4b1044010fb3e2d43a949",
    );
    await expect(applyLeaf(op, key, value)).resolves.toEqual(expected);
  });

  it("hashes with prehash and length prefix", async () => {
    const op = leaf({
      hash: HashOp.SHA256,
      length: LengthOp.VAR_PROTO,
      prehashValue: HashOp.SHA256,
    });
    const key = toAscii("food"); // 04666f6f64
    // echo -n yet another long string | sha256sum
    const value = toAscii("yet another long string"); // 20a48c2d4f67b9f80374938535285ed285819d8a5a8fc1fccd1e3244e437cf290d
    // echo -n 04666f6f6420a48c2d4f67b9f80374938535285ed285819d8a5a8fc1fccd1e3244e437cf290d | xxd -r -p | sha256sum
    const expected = fromHex(
      "87e0483e8fb624aef2e2f7b13f4166cda485baa8e39f437c83d74c94bedb148f",
    );
    await expect(applyLeaf(op, key, value)).resolves.toEqual(expected);
  });

  it("requires key", async () => {
    const op = leaf({
      hash: HashOp.SHA256,
    });
    const key = toAscii("food");
    const value = toAscii("");
    await expect(applyLeaf(op, key, value)).rejects.toThrow();
  });

  it("requires value", async () => {
    const op = leaf({
      hash: HashOp.SHA256,
    });
    const key = toAscii("");
    const value = toAscii("time");
    await expect(applyLeaf(op, key, value)).rejects.toThrow();
  });
});

describe("applyInner", () => {
  it("hash child with prefix and suffix", async () => {
    const op = inner({
      hash: HashOp.SHA256,
      prefix: fromHex("0123456789"),
      suffix: fromHex("deadbeef"),
    });
    const child = fromHex("00cafe00");
    // echo -n 012345678900cafe00deadbeef | xxd -r -p | sha256sum
    const expected = fromHex(
      "0339f76086684506a6d42a60da4b5a719febd4d96d8b8d85ae92849e3a849a5e",
    );
    await expect(applyInner(op, child)).resolves.toEqual(expected);
  });

  it("requies child", async () => {
    const op = inner({
      hash: HashOp.SHA256,
      prefix: fromHex("0123456789"),
      suffix: fromHex("deadbeef"),
    });
    await expect(applyInner(op, fromHex(""))).rejects.toThrow();
  });

  it("hash child with only prefix", async () => {
    const op = inner({
      hash: HashOp.SHA256,
      prefix: fromHex("00204080a0c0e0"),
    });
    const child = fromHex("ffccbb997755331100");
    // echo -n 00204080a0c0e0ffccbb997755331100 | xxd -r -p | sha256sum
    const expected = fromHex(
      "45bece1678cf2e9f4f2ae033e546fc35a2081b2415edcb13121a0e908dca1927",
    );
    await expect(applyInner(op, child)).resolves.toEqual(expected);
  });

  it("hash child with only suffix", async () => {
    const op = inner({
      hash: HashOp.SHA256,
      suffix: toAscii(" just kidding!"),
    });
    const child = toAscii("this is a sha256 hash, really....");
    // echo -n 'this is a sha256 hash, really.... just kidding!'  | sha256sum
    const expected = fromHex(
      "79ef671d27e42a53fba2201c1bbc529a099af578ee8a38df140795db0ae2184b",
    );
    await expect(applyInner(op, child)).resolves.toEqual(expected);
  });
});
