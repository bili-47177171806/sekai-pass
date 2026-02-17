// SPDX-License-Identifier: Apache-2.0
/**
 * PoW solver — spawns a Web Worker for sync SHA-256 hashing
 */

export function solvePoW(challenge, difficulty) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('/js/pow-worker.js');
    worker.onmessage = (e) => {
      resolve(e.data.nonce);
      worker.terminate();
    };
    worker.onerror = (e) => {
      reject(new Error('PoW worker error: ' + e.message));
      worker.terminate();
    };
    worker.postMessage({ challenge, difficulty });
  });
}
