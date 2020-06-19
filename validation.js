"use strict";

const { createHash } = require("crypto");
const signing = require("./signing");

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = (transaction) => {
  if (transaction.amount < 0) return false;
  if (
    !signing.verify(
      transaction.source,
      transaction.source + transaction.recipient + transaction.amount,
      transaction.signature
    )
  )
    return false;
  return true;
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = (block) => {
  const transactionString = block.transactions
    .map((t) => t.signature)
    .toString();
  const toHash = block.previousHash + transactionString + block.nonce;

  if (block.hash !== createHash("sha512").update(toHash).digest("hex")) {
    return false;
  }

  if (!block.transactions.every(isValidTransaction)) return false;
  return true;
};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */

/**  if (!blockchain.genesisBlock) return false;
  if (!isValidBlock(blockchain.blocks)) return false;
  return blocks.map((b) => b.transactions).every(isValidTransaction); **/
const isValidChain = (blockchain) => {
  if (blockchain.blocks[0].previousHash !== null) {
    return false;
  }

  for (let i = 1; i < blockchain.blocks.length; i++) {
    if (blockchain.blocks[i].previousHash !== blockchain.blocks[i - 1].hash)
      return false;
  }

  for (let i = 1; i < blockchain.blocks.length; i++) {
    if (!isValidBlock(blockchain.blocks[i])) return false;
  }

  return blockchain.blocks
    .map((b) => b.transactions)
    .reduce((flat, t) => flat.concat(t), [])
    .every(isValidTransaction);
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = (blockchain) => {
  blockchain.blocks[1].transactions[0].amount = 576579;
};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain,
};
