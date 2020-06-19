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
  if (block.calculateHash(block.nonce) !== block.hash) return false;
  if (!isValidTransaction(block.transactions)) return false;
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
const isValidChain = (blockchain) => {
  if (!blockchain.genesisBlock) return false;
  if (blockchain.blocks.map((t) => t.hash) == null && !block.genesisBlock)
    return false;
  if (
    blockchain.blocks.map((t) => t.previousHash) == null &&
    !block.genesisBlock
  )
    return false;
  if (!isValidBlock(blockchain.blocks)) return false;
  if (!isValidTransaction(blockchain.blocks.transactions)) return false;

  return true;
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = (blockchain) => {
  // Your code here
};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain,
};
