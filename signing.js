"use strict";

const secp256k1 = require("secp256k1");
const { randomBytes, createHash } = require("crypto");

/**
 * A function which generates a new random Secp256k1 private key, returning
 * it as a 64 character hexadecimal string.
 *
 * Example:
 *   const privateKey = createPrivateKey();
 *   console.log(privateKey);
 *   // 'e291df3eede7f0c520fddbe5e9e53434ff7ef3c0894ed9d9cbcb6596f1cfe87e'
 */

const createPrivateKey = () => {
  const random = randomBytes(32);
  const hex = random.toString("hex");
  return hex;
};

const privateKey = createPrivateKey();
console.log(privateKey);

/**
 * A function which takes a hexadecimal private key and returns its public pair
 * as a 66 character hexadecimal string.
 *
 * Example:
 *   const publicKey = getPublicKey(privateKey);
 *   console.log(publicKey);
 *   // '0202694593ddc71061e622222ed400f5373cfa7ea607ce106cca3f039b0f9a0123'
 *
 * Hint:
 *   Remember that the secp256k1-node library expects raw bytes (i.e Buffers),
 *   not hex strings! You'll have to convert the private key.
 */
const getPublicKey = (privateKey) => {
  const buffer = Buffer.from(privateKey, "hex");

  const pub = secp256k1.publicKeyCreate(buffer);
  return pub.toString("hex");
};

const publicKey = getPublicKey(privateKey);
console.log(publicKey);

/**
 * A function which takes a hex private key and a string message, returning
 * a 128 character hexadecimal signature.
 *
 * Example:
 *   const signature = sign(privateKey, 'Hello World!');
 *   console.log(signature);
 *   // '4ae1f0b20382ad628804a5a66e09cc6bdf2c83fa64f8017e98d84cc75a1a71b52...'
 *
 * Hint:
 *   Remember that you need to sign a SHA-256 hash of the message,
 *   not the message itself!
 */

const sign = (privateKey, message) => {
  const messges = createHash("sha256").update(message).digest();
  const buffer = Buffer.from(privateKey, "hex");
  const { signature } = secp256k1.sign(messges, buffer);
  return signature.toString("hex");
};

const signature = sign(privateKey, "Hello World!");
console.log(signature);

/**
 * A function which takes a hex public key, a string message, and a hex
 * signature, and returns either true or false.
 *
 * Example:
 *   console.log( verify(publicKey, 'Hello World!', signature) );
 *   // true
 *   console.log( verify(publicKey, 'Hello World?', signature) );
 *   // false
 */

const verify = (publicKey, message, signature) => {
  const msg = createHash("sha256").update(message).digest();
  const buffer1 = Buffer.from(signature, "hex");
  const buffer2 = Buffer.from(publicKey, "hex");
  return secp256k1.verify(msg, buffer1, buffer2);
};
console.log(verify(publicKey, "Hello World!", signature));
console.log(verify(publicKey, "Hello World?", signature));

module.exports = {
  createPrivateKey,
  getPublicKey,
  sign,
  verify,
};
