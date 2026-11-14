// Zero-dependency WebAuthn (CBOR + COSE + Web Crypto) verification helpers

const te = new TextEncoder();
const td = new TextDecoder();

export function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(input: string): Uint8Array {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((input.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

interface CborCursor {
  bytes: Uint8Array;
  view: DataView;
  offset: number;
}

function readCborUint(cur: CborCursor, ai: number): number {
  if (ai < 24) return ai;
  if (ai === 24) {
    if (cur.offset + 1 > cur.bytes.length) throw new Error('Unexpected EOF reading CBOR uint8');
    return cur.bytes[cur.offset++];
  }
  if (ai === 25) {
    if (cur.offset + 2 > cur.bytes.length) throw new Error('Unexpected EOF reading CBOR uint16');
    const v = cur.view.getUint16(cur.offset, false);
    cur.offset += 2;
    return v;
  }
  if (ai === 26) {
    if (cur.offset + 4 > cur.bytes.length) throw new Error('Unexpected EOF reading CBOR uint32');
    const v = cur.view.getUint32(cur.offset, false);
    cur.offset += 4;
    return v;
  }
  if (ai === 27) {
    if (cur.offset + 8 > cur.bytes.length) throw new Error('Unexpected EOF reading CBOR uint64');
    const big = cur.view.getBigUint64(cur.offset, false);
    cur.offset += 8;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR integer exceeds safe range');
    return Number(big);
  }
  throw new Error(`Unsupported CBOR additional info: ${ai}`);
}

function readCborItem(cur: CborCursor): unknown {
  if (cur.offset >= cur.bytes.length) throw new Error('Unexpected EOF reading CBOR item');
  const initial = cur.bytes[cur.offset++];
  const major = initial >> 5;
  const ai = initial & 0x1f;

  switch (major) {
    case 0:
      return readCborUint(cur, ai);
    case 1:
      return -1 - readCborUint(cur, ai);
    case 2: {
      const len = readCborUint(cur, ai);
      if (cur.offset + len > cur.bytes.length) throw new Error('Unexpected EOF reading CBOR bytes');
      const slice = cur.bytes.slice(cur.offset, cur.offset + len);
      cur.offset += len;
      return slice;
    }
    case 3: {
      const len = readCborUint(cur, ai);
      if (cur.offset + len > cur.bytes.length) throw new Error('Unexpected EOF reading CBOR text');
      const slice = cur.bytes.subarray(cur.offset, cur.offset + len);
      cur.offset += len;
      return td.decode(slice);
    }
    case 4: {
      const len = readCborUint(cur, ai);
      const arr: unknown[] = [];
      for (let i = 0; i < len; i++) arr.push(readCborItem(cur));
      return arr;
    }
    case 5: {
      const len = readCborUint(cur, ai);
      const map = new Map<unknown, unknown>();
      for (let i = 0; i < len; i++) {
        const key = readCborItem(cur);
        const val = readCborItem(cur);
        map.set(key, val);
      }
      return map;
    }
    case 6: {
      readCborUint(cur, ai);
      return readCborItem(cur);
    }
    case 7: {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 26 && cur.offset + 4 <= cur.bytes.length) {
        const v = cur.view.getFloat32(cur.offset, false);
        cur.offset += 4;
        return v;
      }
      if (ai === 27 && cur.offset + 8 <= cur.bytes.length) {
        const v = cur.view.getFloat64(cur.offset, false);
        cur.offset += 8;
        return v;
      }
      throw new Error(`Unsupported CBOR simple value: ${ai}`);
    }
    default:
      throw new Error(`Unsupported CBOR major type: ${major}`);
  }
}

export function decodeCbor(bytes: Uint8Array): { value: unknown; bytesRead: number } {
  const cur: CborCursor = {
    bytes,
    view: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    offset: 0,
  };
  const value = readCborItem(cur);
  return { value, bytesRead: cur.offset };
}

export interface ParsedCoseKey {
  jwk: JsonWebKey;
  alg: -7 | -257;
}

export function coseKeyToJwk(coseBytes: Uint8Array): ParsedCoseKey {
  const { value } = decodeCbor(coseBytes);
  if (!(value instanceof Map)) throw new Error('COSE key must be a CBOR map');

  const kty = value.get(1);
  const alg = value.get(3);

  // EC2 (P-256 / ES256)
  if (kty === 2 && (alg === -7 || alg === undefined)) {
    const crv = value.get(-1);
    const x = value.get(-2);
    const y = value.get(-3);
    if (crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
      throw new Error('Invalid EC2 COSE key parameters');
    }
    return {
      alg: -7,
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: toBase64Url(x),
        y: toBase64Url(y),
        ext: true,
      },
    };
  }

  // RSA (RS256)
  if (kty === 3 && (alg === -257 || alg === undefined)) {
    const n = value.get(-1);
    const e = value.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array) || n.length < 128) {
      throw new Error('Invalid RSA COSE key parameters');
    }
    return {
      alg: -257,
      jwk: {
        kty: 'RSA',
        n: toBase64Url(n),
        e: toBase64Url(e),
        ext: true,
      },
    };
  }

  throw new Error('Unsupported WebAuthn COSE key type or algorithm');
}

export interface ParsedAuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  userPresent: boolean;
  userVerified: boolean;
  attestedCredentialDataIncluded: boolean;
  signCount: number;
  credentialId?: Uint8Array;
  coseKey?: ParsedCoseKey;
}

export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData {
  if (authData.length < 37) throw new Error('Authenticator data too short');
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  const rpIdHash = authData.subarray(0, 32);
  const flags = authData[32];
  const signCount = view.getUint32(33, false);

  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  const attestedCredentialDataIncluded = (flags & 0x40) !== 0;

  let credentialId: Uint8Array | undefined;
  let coseKey: ParsedCoseKey | undefined;

  if (attestedCredentialDataIncluded) {
    if (authData.length < 55) throw new Error('Attested credential data truncated');
    const credIdLen = view.getUint16(53, false);
    const credEnd = 55 + credIdLen;
    if (credEnd > authData.length) throw new Error('Credential ID length out of bounds');
    credentialId = authData.slice(55, credEnd);
    coseKey = coseKeyToJwk(authData.subarray(credEnd));
  }

  return {
    rpIdHash,
    flags,
    userPresent,
    userVerified,
    attestedCredentialDataIncluded,
    signCount,
    credentialId,
    coseKey,
  };
}

function derEcdsaToP1363(der: Uint8Array, partLength = 32): Uint8Array {
  // Some test callers or exotic authenticators may already pass raw 64-byte P1363 signatures
  if (der.length === partLength * 2 && der[0] !== 0x30) {
    return der;
  }
  if (der.length < 8 || der[0] !== 0x30) throw new Error('Invalid DER ECDSA signature');
  let offset = 2;
  if (der[1] & 0x80) {
    const lenBytes = der[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (der[offset] !== 0x02) throw new Error('Invalid DER ECDSA r tag');
  const rLen = der[offset + 1];
  const rBytes = der.subarray(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;

  if (der[offset] !== 0x02) throw new Error('Invalid DER ECDSA s tag');
  const sLen = der[offset + 1];
  const sBytes = der.subarray(offset + 2, offset + 2 + sLen);

  const out = new Uint8Array(partLength * 2);
  const rTrim = rBytes.length > partLength ? rBytes.subarray(rBytes.length - partLength) : rBytes;
  const sTrim = sBytes.length > partLength ? sBytes.subarray(sBytes.length - partLength) : sBytes;
  out.set(rTrim, partLength - rTrim.length);
  out.set(sTrim, partLength * 2 - sTrim.length);
  return out;
}

async function importCosePublicKey(jwk: JsonWebKey, alg: -7 | -257): Promise<CryptoKey> {
  if (alg === -7) {
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  }
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
}

function parseClientData(clientDataB64u: string, expectedType: string, expectedChallenge: string, expectedOrigin: string): Uint8Array {
  const bytes = fromBase64Url(clientDataB64u);
  const json = JSON.parse(td.decode(bytes)) as { type?: string; challenge?: string; origin?: string };
  if (json.type !== expectedType) throw new Error('Invalid WebAuthn clientData type');
  if (json.challenge !== expectedChallenge) throw new Error('WebAuthn challenge mismatch');
  if (json.origin !== expectedOrigin) throw new Error('WebAuthn origin mismatch');
  return bytes;
}

export async function verifyRegistrationResponse(opts: {
  clientDataJSON: string;
  attestationObject: string;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRpId: string;
}): Promise<{ credentialId: string; publicKeyJwkJson: string; alg: -7 | -257; signCount: number }> {
  parseClientData(opts.clientDataJSON, 'webauthn.create', opts.expectedChallenge, opts.expectedOrigin);

  const attestationBytes = fromBase64Url(opts.attestationObject);
  const { value: attMap } = decodeCbor(attestationBytes);
  if (!(attMap instanceof Map)) throw new Error('Invalid attestationObject');

  const authDataBytes = attMap.get('authData');
  if (!(authDataBytes instanceof Uint8Array)) throw new Error('Missing authData in attestationObject');

  const parsed = parseAuthenticatorData(authDataBytes);
  const expectedRpHash = await sha256(te.encode(opts.expectedRpId));
  if (!bytesEqual(parsed.rpIdHash, expectedRpHash)) throw new Error('RP ID hash mismatch');
  if (!parsed.userPresent) throw new Error('User presence flag not set');
  if (!parsed.attestedCredentialDataIncluded || !parsed.credentialId || !parsed.coseKey) {
    throw new Error('Attested credential data missing');
  }

  // Validate key imports cleanly in Web Crypto before persisting
  await importCosePublicKey(parsed.coseKey.jwk, parsed.coseKey.alg);

  return {
    credentialId: toBase64Url(parsed.credentialId),
    publicKeyJwkJson: JSON.stringify(parsed.coseKey.jwk),
    alg: parsed.coseKey.alg,
    signCount: parsed.signCount,
  };
}

export async function verifyAssertionResponse(opts: {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRpId: string;
  publicKeyJwkJson: string;
  alg: number;
  previousSignCount: number;
}): Promise<{ verified: boolean; newSignCount: number }> {
  const clientDataBytes = parseClientData(opts.clientDataJSON, 'webauthn.get', opts.expectedChallenge, opts.expectedOrigin);
  const authDataBytes = fromBase64Url(opts.authenticatorData);
  const signatureBytes = fromBase64Url(opts.signature);

  const parsed = parseAuthenticatorData(authDataBytes);
  const expectedRpHash = await sha256(te.encode(opts.expectedRpId));
  if (!bytesEqual(parsed.rpIdHash, expectedRpHash)) throw new Error('RP ID hash mismatch');
  if (!parsed.userPresent) throw new Error('User presence flag not set');

  if ((opts.previousSignCount > 0 || parsed.signCount > 0) && parsed.signCount <= opts.previousSignCount) {
    throw new Error('Authenticator signature counter did not advance');
  }

  if (opts.alg !== -7 && opts.alg !== -257) {
    throw new Error('Unsupported stored passkey algorithm');
  }

  const jwk = JSON.parse(opts.publicKeyJwkJson) as JsonWebKey;
  const key = await importCosePublicKey(jwk, opts.alg);
  const clientHash = await sha256(clientDataBytes);
  const signedData = new Uint8Array(authDataBytes.length + clientHash.length);
  signedData.set(authDataBytes, 0);
  signedData.set(clientHash, authDataBytes.length);

  const verified =
    opts.alg === -7
      ? await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          key,
          derEcdsaToP1363(signatureBytes),
          signedData
        )
      : await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signatureBytes, signedData);

  return { verified, newSignCount: parsed.signCount };
}
