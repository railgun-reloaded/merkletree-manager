import { MerkleHelper } from './helper'

/**
 * The `MerkleManager` class is responsible for managing UTXO (Unspent Transaction Outputs)
 * and transaction identifiers within a Merkle tree structure. It provides functionality
 * for inserting leaves into the Merkle tree, managing nullifiers, and verifying cryptographic
 * proofs. This class utilizes the `MerkleHelper` to perform operations on the Merkle tree.
 * - The `utxo` property represents a Merkle tree for UTXO data.
 * - The `txid` property represents a Merkle tree for transaction identifiers.
 * - The `nullifiers` property is a set used to track unique identifiers or prevent double-spending.
 * @example
 * ```typescript
 * const manager = new MerkleManager(16);
 * manager.insertTXIDLeaves([new Uint8Array([1, 2, 3])], 0);
 * manager.insertNullifier('unique-nullifier');
 * const exists = manager.checkNullifier('unique-nullifier');
 * console.log(exists); // true
 * ```
 */
export class MerkleManager {
  /**
   * Represents a MerkleHelper instance used to manage UTXO (Unspent Transaction Outputs)
   * within a Merkle tree structure. This helper facilitates operations such as
   * adding, verifying, and managing UTXO data in the context of cryptographic proofs.
   */
  utxo: MerkleHelper
  /**
   * Represents a transaction identifier managed by the MerkleHelper.
   * This property is used to interact with and manage Merkle tree operations
   * related to specific transactions.
   */
  txid: MerkleHelper
  /**
   * A set of nullifiers used to track unique identifiers or prevent double-spending.
   * Each nullifier is represented as a string and stored in a Set to ensure uniqueness.
   */
  nullifiers: Set<string>

  /**
   * Constructs a new instance of the manager with specified tree depth.
   * Initializes MerkleHelper instances for `utxo` and `txid` with the given tree depth.
   * Also initializes an empty set for `nullifiers`.
   * @param treeDepth - The depth of the Merkle tree. Defaults to 16 if not provided.
   */
  constructor (treeDepth = 16) {
    this.utxo = new MerkleHelper(treeDepth)
    this.txid = new MerkleHelper(treeDepth)
    this.nullifiers = new Set()
  }

  /**
   * Inserts an array of UTXO leaves into the Merkle tree starting at the specified position.
   * @param leaves - An array of Uint8Array objects representing the UTXO leaves to be inserted.
   * @param startPosition - The starting position in the Merkle tree where the leaves will be inserted.
   */
  insertTXIDLeaves (leaves: Uint8Array[], startPosition: number): void {
    this.txid.insertLeaves(leaves, startPosition)
  }

  /**
   * Adds a new nullifier to the set
   * @param nullifier - The nullifier to add
   */
  insertNullifier (nullifier: string): void {
    if (this.nullifiers.has(nullifier)) {
      throw new Error('Nullifier already exists')
    }
    this.nullifiers.add(nullifier)
    // console.log("Nullifier added");
  }

  /**
   * Checks if a nullifier exists in the set
   * @param nullifier - The nullifier to check
   * @returns True if the nullifier exists, false otherwise
   */
  checkNullifier (nullifier: string): boolean {
    return this.nullifiers.has(nullifier)
  }
}
