// Pure-JS Keccak-256 (original Keccak padding 0x01, NOT SHA3-256's 0x06).
// Used to map the string task_id to a field element: keccak256(task_id) mod p.
// BigInt implementation — slow but correct; called once per proof.
// Test vectors: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
// keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45

const MASK64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const PI = [
  [0, 3, 1, 4, 2], [2, 0, 3, 1, 4], [4, 2, 0, 3, 1],
  [1, 4, 2, 0, 3], [3, 1, 4, 2, 0],
]; // PI[x][y] = (2x + 3y) mod 5

function rotl(x, n) {
  return n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

function keccakF1600(s) {
  for (let round = 0; round < 24; round++) {
    // Theta
    const C = [];
    for (let x = 0; x < 5; x++) C[x] = s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4];
    const D = [];
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x][y] ^= D[x];
    // Rho + Pi
    const B = Array.from({ length: 5 }, () => Array(5).fill(0n));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y][PI[x][y]] = rotl(s[x][y], ROT[x][y]);
    // Chi
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      s[x][y] = B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y]);
    // Iota
    s[0][0] ^= RC[round];
  }
}

export function keccak256(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const rate = 136; // bytes for Keccak-256
  const state = Array.from({ length: 5 }, () => Array(5).fill(0n));
  // absorb full blocks
  let off = 0;
  while (off + rate <= bytes.length) {
    for (let i = 0; i < rate; i++) {
      // byte i -> lane floor(i/8), byte-in-lane i%8, lane (x,y) with index x+5y
      const lane = Math.floor(i / 8), b = i % 8;
      const lx = lane % 5, ly = Math.floor(lane / 5);
      state[lx][ly] ^= BigInt(bytes[off + i]) << BigInt(8 * b);
    }
    keccakF1600(state);
    off += rate;
  }
  // final block with pad10*1 (Keccak: 0x01 ... 0x80)
  const rem = bytes.length - off;
  const block = new Uint8Array(rate);
  block.set(bytes.slice(off));
  block[rem] ^= 0x01;
  block[rate - 1] ^= 0x80;
  for (let i = 0; i < rate; i++) {
    const lane = Math.floor(i / 8), b = i % 8;
    const lx = lane % 5, ly = Math.floor(lane / 5);
    state[lx][ly] ^= BigInt(block[i]) << BigInt(8 * b);
  }
  keccakF1600(state);
  // squeeze 32 bytes, little-endian per lane, lanes in x-major order
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const lane = Math.floor(i / 8), b = i % 8;
    const lx = lane % 5, ly = Math.floor(lane / 5);
    out[i] = Number((state[lx][ly] >> BigInt(8 * b)) & 0xffn);
  }
  return out;
}

export function keccak256Hex(input) {
  return "0x" + [...keccak256(input)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
