import { fromByteArray, toByteArray } from "base64-js";

const ENCODER = new TextEncoder();

export function arrayToB64(array: Uint8Array): string {
  return fromByteArray(array)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function b64ToArray(str: string): Uint8Array {
  return toByteArray(str + "===".slice((str.length + 3) % 4));
}

export async function concatKdf(key: Uint8Array, enc: string) {
  if (key.length !== 32) {
    throw new Error("unsupported key length");
  }
  const otherInfo = getOtherInfo(enc);
  const buffer = new ArrayBuffer(4 + key.length + otherInfo.length);
  const dv = new DataView(buffer);
  const concat = new Uint8Array(buffer);
  dv.setUint32(0, 1);
  concat.set(key, 4);
  concat.set(otherInfo, key.length + 4);
  const result = await crypto.subtle.digest("SHA-256", concat);
  return new Uint8Array(result);
}

export function getOtherInfo(enc: string) {
  const name = ENCODER.encode(enc);
  const length = 256;
  const buffer = new ArrayBuffer(name.length + 16);
  const dv = new DataView(buffer);
  const result = new Uint8Array(buffer);
  let i = 0;
  dv.setUint32(i, name.length);
  i += 4;
  result.set(name, i);
  i += name.length;
  dv.setUint32(i, 0);
  i += 4;
  dv.setUint32(i, 0);
  i += 4;
  dv.setUint32(i, length);
  return result;
}

export function concat(b1: Uint8Array, b2: Uint8Array) {
  const result = new Uint8Array(b1.length + b2.length);
  result.set(b1, 0);
  result.set(b2, b1.length);
  return result;
}
