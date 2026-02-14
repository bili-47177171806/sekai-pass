/**
 * Stateful Proof-of-Work challenge system
 * Server controls when PoW is allowed via KV-stored challenge state
 */

const POW_DIFFICULTY = 20; // ~1M hashes, ~1-2s with sync SHA-256

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(data: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hasLeadingZeroBits(hexHash: string, bits: number): boolean {
  const fullNibbles = Math.floor(bits / 4);
  const remainBits = bits % 4;

  for (let i = 0; i < fullNibbles; i++) {
    if (hexHash[i] !== '0') return false;
  }

  if (remainBits > 0) {
    const nibble = parseInt(hexHash[fullNibbles], 16);
    if (nibble >= (1 << (4 - remainBits))) return false;
  }

  return true;
}

export interface ChallengeState {
  ip: string;
  issued: number;
  turnstileAttempted: boolean;
  powIssued: boolean;
  powChallenge: string | null;
  used: boolean;
}

export function createChallengeState(ip: string): ChallengeState {
  return {
    ip,
    issued: Date.now(),
    turnstileAttempted: false,
    powIssued: false,
    powChallenge: null,
    used: false,
  };
}

export function generatePoWChallenge(): { challenge: string; difficulty: number } {
  return { challenge: randomHex(16), difficulty: POW_DIFFICULTY };
}

export async function verifyPoWHash(challenge: string, nonce: string): Promise<boolean> {
  const hash = await sha256Hex(challenge + nonce);
  return hasLeadingZeroBits(hash, POW_DIFFICULTY);
}
