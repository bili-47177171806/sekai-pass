/*
 * Copyright 2026 The 25-ji-code-de Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


// Decrypt client-encrypted password
export function decryptPassword(encryptedPassword: string): string {
  try {
    // Decode base64
    const decoded = atob(encryptedPassword);
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {
      bytes[i] = decoded.charCodeAt(i);
    }

    // Convert to string
    const decoder = new TextDecoder();
    const combined = decoder.decode(bytes);

    // Split by delimiter
    const parts = combined.split('|');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted password format');
    }

    const [password, salt, timestamp] = parts;

    // Validate timestamp (within 5 minutes)
    const now = Date.now();
    const ts = parseInt(timestamp);
    if (isNaN(ts) || Math.abs(now - ts) > 5 * 60 * 1000) {
      throw new Error('Password encryption expired');
    }

    return password;
  } catch (error) {
    throw new Error('Failed to decrypt password');
  }
}

// Validate request parameters
export function validateRequest(
  nonce: string | null,
  fingerprint: string | null,
  timestamp: string | null
): boolean {
  if (!nonce || !fingerprint || !timestamp) {
    return false;
  }

  // Validate nonce format (32 hex characters)
  if (!/^[0-9a-f]{32}$/.test(nonce)) {
    return false;
  }

  // Validate timestamp (within 5 minutes)
  const now = Date.now();
  const ts = parseInt(timestamp);
  if (isNaN(ts) || Math.abs(now - ts) > 5 * 60 * 1000) {
    return false;
  }

  return true;
}
