// JWT Implementation using Web Crypto API
// Supports ES256 (ECDSA with P-256 and SHA-256)

/**
 * Base64URL encode (RFC 4648)
 */
export function base64URLEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64URL decode
 */
export function base64URLDecode(str: string): ArrayBuffer {
  // Add padding if needed
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }

  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Sign JWT using ES256
 */
export async function signJWT(
  payload: Record<string, any>,
  privateKeyJWK: JsonWebKey,
  kid: string
): Promise<string> {
  // Import private key
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJWK,
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    false,
    ["sign"]
  );

  // Create header
  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: kid
  };

  // Encode header and payload
  const encodedHeader = base64URLEncode(
    new TextEncoder().encode(JSON.stringify(header))
  );
  const encodedPayload = base64URLEncode(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  // Create signing input
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signingInputBuffer = new TextEncoder().encode(signingInput);

  // Sign
  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" }
    },
    privateKey,
    signingInputBuffer
  );

  // Encode signature
  const encodedSignature = base64URLEncode(signature);

  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verify JWT signature using ES256
 */
export async function verifyJWT(
  token: string,
  publicKeyJWK: JsonWebKey
): Promise<boolean> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    // Import public key
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicKeyJWK,
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      false,
      ["verify"]
    );

    // Decode signature
    const signature = base64URLDecode(encodedSignature);

    // Create signing input
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signingInputBuffer = new TextEncoder().encode(signingInput);

    // Verify signature
    return await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" }
      },
      publicKey,
      signature,
      signingInputBuffer
    );
  } catch (error) {
    console.error("JWT verification error:", error);
    return false;
  }
}

/**
 * Decode JWT without verification (for inspection)
 */
export function decodeJWT(token: string): {
  header: any;
  payload: any;
  signature: string;
} | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    const header = JSON.parse(
      new TextDecoder().decode(base64URLDecode(encodedHeader))
    );
    const payload = JSON.parse(
      new TextDecoder().decode(base64URLDecode(encodedPayload))
    );

    return {
      header,
      payload,
      signature: encodedSignature
    };
  } catch (error) {
    console.error("JWT decode error:", error);
    return null;
  }
}
