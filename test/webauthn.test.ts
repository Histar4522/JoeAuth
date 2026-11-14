import { describe, expect, it } from 'vitest';
import {
  fromBase64Url,
  toBase64Url,
  verifyAssertionResponse,
  verifyRegistrationResponse,
} from '../src/lib/webauthn';

// Minimal CBOR encoder for generating WebAuthn fixtures in unit tests
function cborUint(major: number, n: number): number[] {
  const prefix = major << 5;
  if (n < 24) return [prefix | n];
  if (n < 256) return [prefix | 24, n];
  if (n < 65536) return [prefix | 25, (n >> 8) & 0xff, n & 0xff];
  return [prefix | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function encodeCbor(val: unknown): Uint8Array {
  if (typeof val === 'number') {
    if (val >= 0) return new Uint8Array(cborUint(0, val));
    return new Uint8Array(cborUint(1, -1 - val));
  }
  if (typeof val === 'string') {
    const bytes = new TextEncoder().encode(val);
    return new Uint8Array([...cborUint(3, bytes.length), ...bytes]);
  }
  if (val instanceof Uint8Array) {
    return new Uint8Array([...cborUint(2, val.length), ...val]);
  }
  if (val instanceof Map) {
    const parts: number[] = [...cborUint(5, val.size)];
    for (const [k, v] of val.entries()) {
      parts.push(...encodeCbor(k), ...encodeCbor(v));
    }
    return new Uint8Array(parts);
  }
  if (Array.isArray(val)) {
    const parts: number[] = [...cborUint(4, val.length)];
    for (const item of val) parts.push(...encodeCbor(item));
    return new Uint8Array(parts);
  }
  throw new Error('Unsupported test CBOR value');
}

function p1363ToDerEcdsa(sig: Uint8Array): Uint8Array {
  const encodeInt = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let trimmed = bytes.subarray(i);
    if (trimmed[0] & 0x80) {
      trimmed = new Uint8Array([0, ...trimmed]);
    }
    return new Uint8Array([0x02, trimmed.length, ...trimmed]);
  };
  const r = encodeInt(sig.subarray(0, 32));
  const s = encodeInt(sig.subarray(32, 64));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

describe('Zero-dependency WebAuthn CBOR + Web Crypto verifier', () => {
  it('verifies P-256 registration attestation and DER ECDSA authentication assertions', async () => {
    const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const pubJwk = (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey;
    const xBytes = fromBase64Url(pubJwk.x!);
    const yBytes = fromBase64Url(pubJwk.y!);

    const coseMap = new Map<unknown, unknown>([
      [1, 2], // EC2
      [3, -7], // ES256
      [-1, 1], // P-256
      [-2, xBytes],
      [-3, yBytes],
    ]);
    const coseBytes = encodeCbor(coseMap);
    const credId = crypto.getRandomValues(new Uint8Array(32));
    const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('localhost')));

    const regAuthData = new Uint8Array(37 + 16 + 2 + credId.length + coseBytes.length);
    regAuthData.set(rpIdHash, 0);
    regAuthData[32] = 0x45; // UP | UV | AT
    new DataView(regAuthData.buffer).setUint32(33, 1, false);
    // 37..53 zero AAGUID
    new DataView(regAuthData.buffer).setUint16(53, credId.length, false);
    regAuthData.set(credId, 55);
    regAuthData.set(coseBytes, 55 + credId.length);

    const attObj = encodeCbor(
      new Map<unknown, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', regAuthData],
      ])
    );

    const regChallenge = 'test-reg-challenge-123';
    const regClientData = toBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: regChallenge,
          origin: 'http://localhost',
        })
      )
    );

    const reg = await verifyRegistrationResponse({
      clientDataJSON: regClientData,
      attestationObject: toBase64Url(attObj),
      expectedChallenge: regChallenge,
      expectedOrigin: 'http://localhost',
      expectedRpId: 'localhost',
    });

    expect(reg.credentialId).toBe(toBase64Url(credId));
    expect(reg.alg).toBe(-7);
    expect(reg.signCount).toBe(1);

    // Now test assertion with DER ECDSA signature and advancing counter
    const loginChallenge = 'test-login-challenge-456';
    const loginClientBytes = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: loginChallenge,
        origin: 'http://localhost',
      })
    );
    const loginAuthData = new Uint8Array(37);
    loginAuthData.set(rpIdHash, 0);
    loginAuthData[32] = 0x05; // UP | UV
    new DataView(loginAuthData.buffer).setUint32(33, 2, false);

    const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', loginClientBytes));
    const signedData = new Uint8Array(loginAuthData.length + clientHash.length);
    signedData.set(loginAuthData, 0);
    signedData.set(clientHash, loginAuthData.length);

    const rawSig = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signedData)
    );
    const derSig = p1363ToDerEcdsa(rawSig);

    const asserted = await verifyAssertionResponse({
      clientDataJSON: toBase64Url(loginClientBytes),
      authenticatorData: toBase64Url(loginAuthData),
      signature: toBase64Url(derSig),
      expectedChallenge: loginChallenge,
      expectedOrigin: 'http://localhost',
      expectedRpId: 'localhost',
      publicKeyJwkJson: reg.publicKeyJwkJson,
      alg: reg.alg,
      previousSignCount: reg.signCount,
    });
    expect(asserted.verified).toBe(true);
    expect(asserted.newSignCount).toBe(2);

    // Stale signCount must be rejected (cloned authenticator check)
    await expect(
      verifyAssertionResponse({
        clientDataJSON: toBase64Url(loginClientBytes),
        authenticatorData: toBase64Url(loginAuthData),
        signature: toBase64Url(derSig),
        expectedChallenge: loginChallenge,
        expectedOrigin: 'http://localhost',
        expectedRpId: 'localhost',
        publicKeyJwkJson: reg.publicKeyJwkJson,
        alg: reg.alg,
        previousSignCount: 2,
      })
    ).rejects.toThrow();
  });
});
