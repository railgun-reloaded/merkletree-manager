import { arrayToBigInt, bytesToHex, poseidonFunc } from '@railgun-reloaded/cryptography'

import { arrayToByteLength, bigIntToArray } from './bytes'
import { ZERO_HASH_BIGINT } from './constants'

interface MerkleProof {
  element: Uint8Array;
  elements: Uint8Array[];
  indices: number;
  root: Uint8Array;
}

/**
 * Represents a Merkle Tree data structure, which is used for efficient and secure verification of data integrity.
 * A Merkle Tree is a binary tree where each leaf node contains a hash of a data block, and each non-leaf node contains
 * the hash of its child nodes. This structure allows for efficient verification of the presence of an element in the tree
 * using Merkle proofs.
 * Features:
 * - Supports creation of Merkle Trees with configurable depth and zero values.
 * - Provides methods for hashing, inserting leaves, rebuilding sparse trees, generating proofs, and validating proofs.
 * - Includes static utility methods for zero value generation and hashing.
 * -
 * This implementation assumes the use of Poseidon hash function for hashing operations and includes helper functions
 * for converting between different data formats (e.g., Uint8Array, bigint).
 * @example
 * ```typescript
 * const depth = 16;
 * const treeNumber = 0;
 * const merkleTree = MerkleTree.createTree(treeNumber, depth);
 * const leaves = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
 * merkleTree.insertLeaves(leaves, 0);
 * const proof = merkleTree.generateProof(leaves[0]);
 * const isValid = MerkleTree.validateProof(proof);
 * console.log(`Proof is valid: ${isValid}`);
 * ```
 */
class MerkleTree {
  /**
   * Represents the unique identifier for a Merkle tree instance.
   * This number is used to distinguish between different trees managed
   * within the application.
   */
  treeNumber: number

  /**
   * Represents the depth of the Merkle tree.
   * The depth determines the number of levels in the tree,
   * where each level corresponds to a layer of nodes.
   * A higher depth results in a larger tree with more nodes.
   */
  depth: number

  /**
   * An array of zero-filled `Uint8Array` objects, typically used as placeholders
   * or default values in the construction of a Merkle tree. Each element in the
   * array represents a zero value at a specific depth or level of the tree.
   */
  zeros: Uint8Array[]

  /**
   * Represents a Merkle tree structure where each level of the tree is an array of Uint8Array nodes.
   * The `tree` is a two-dimensional array, with the outer array representing the levels of the tree
   * and the inner arrays containing the nodes at each level.
   */
  tree: Uint8Array[][]

  /**
   * An array of nullifiers represented as Uint8Array.
   * Nullifiers are used to ensure that a specific action or transaction
   * cannot be performed more than once, typically in cryptographic protocols
   * or zero-knowledge proofs.
   */
  nullifiers: Uint8Array[] = []

  /**
   * Merkle Tree
   * @param treeNumber - merkle tree number
   * @param depth - merkle tree depth
   * @param zeros - zero values for each level of merkle tree
   * @param tree - starting tree
   */
  constructor (
    treeNumber: number,
    depth: number,
    zeros: Uint8Array[],
    tree: Uint8Array[][]
  ) {
    this.treeNumber = treeNumber
    this.depth = depth
    this.zeros = zeros
    this.tree = tree
  }

  /**
   * Gets tree root
   * @returns root
   */
  get root (): Uint8Array {
    // TODO: remove this
    // @ts-expect-error
    return this.tree[this.depth][0]
  }

  /**
   * Gets tree length
   * @returns length
   */
  get length (): number {
    // TODO: remove this
    // @ts-expect-error
    return this.tree[0].length
  }

  /**
   * Hashes 2 merkle nodes
   * @param left - left value to hash
   * @param right - right value to hash
   * @returns hash
   */
  static hashLeftRight (
    left: Uint8Array,
    right: Uint8Array
  ): Uint8Array {
    return poseidonFunc([
      // @ts-expect-error - Uint8Array is allowable input
      arrayToByteLength(left, 32),
      // @ts-expect-error - Uint8Array is allowable input
      arrayToByteLength(right, 32),
    ]) as Uint8Array
  }

  /**
   * Gets zero value for tree
   * @returns zero value
   */
  static get zeroValue (): Uint8Array {
    const railgunHash = ZERO_HASH_BIGINT
    return bigIntToArray(railgunHash, 32)
  }

  /**
   * Gets zero value for each level of a tree
   * @param depth - depth of tree
   * @returns zero values for each level
   */
  static getZeroValueLevels (depth: number): Uint8Array[] {
    // Initialize empty array for levels
    const levels: Uint8Array[] = []

    // First level should be the leaf zero value
    levels.push(this.zeroValue)

    // Loop through remaining levels to root
    for (let level = 1; level < depth; level += 1) {
      // Push left right hash of level below's zero level
      levels.push(
        // TODO: remove this
        // @ts-expect-error
        MerkleTree.hashLeftRight(levels[level - 1], levels[level - 1])
      )
    }

    return levels
  }

  /**
   * Creates a new Merkle tree with the specified parameters.
   * @param treeNumber - The identifier for the tree. Defaults to 0.
   * @param depth - The depth of the Merkle tree. Defaults to 16.
   * @param fromTree - An optional existing Merkle tree to derive the new tree's root from.
   * @returns A promise that resolves to a new instance of the `MerkleTree` class.
   * - The `zeros` array is populated with zero values for each level of the tree.
   * - The `tree` array is initialized with empty arrays for each level, except for the deepest level, which is populated with the root value.
   * - If `fromTree` is provided, its root is used for the deepest level; otherwise, a new root is computed using the zero values.
   */
  static createTree (
    treeNumber = 0,
    depth = 16,
    fromTree?: MerkleTree
  ): MerkleTree {
    const zeros: Uint8Array[] = MerkleTree.getZeroValueLevels(depth)
    const tree: Uint8Array[][] = Array(depth)
      .fill(0)
      .map(() => [])
    tree[depth] = [
      // TODO: remove this
      fromTree?.root ??
      // @ts-expect-error
      (MerkleTree.hashLeftRight(zeros[depth - 1], zeros[depth - 1])),
    ]

    return new MerkleTree(treeNumber, depth, zeros, tree)
  }

  /**
   * Rebuilds tree
   */
  rebuildSparseTree () {
    // Check if tree is empty
    for (let level = 0; level < this.depth; level += 1) {
      this.tree[level + 1] = []

      // TODO: remove this
      // @ts-expect-error
      for (let pos = 0; pos < this.tree[level].length; pos += 2) {
        // TODO: remove this
        // @ts-expect-error
        this.tree[level + 1].push(
          MerkleTree.hashLeftRight(
            // TODO: remove this
            // @ts-expect-error
            this.tree[level][pos],
            // TODO: remove this
            // @ts-expect-error
            this.tree[level][pos + 1] ?? this.zeros[level]
          )
        )
      }
    }
  }

  /**
   * Inserts leaves into tree
   * @param leaves - array of leaves to add
   * @param startPosition - position to start inserting leaves from
   */
  insertLeaves (leaves: Uint8Array[], startPosition: number) {
    if (leaves.length === 0) {
      return
    }

    // Add leaves to tree
    leaves.forEach(
      // TODO: remove this
      // @ts-expect-error
      (leaf, index) => (this.tree[0][startPosition + index] = leaf)
    )

    // Rebuild tree
    // await this.rebuildSparseTree();
  }

  /**
   * Gets Merkle Proof for element
   * @param element - element to get proof for
   * @returns proof
   */
  // TODO: alter this to use the element index instead, we will be caching the nodes also.
  generateProof (element: Uint8Array): MerkleProof {
    // Initialize of proof elements
    const elements = []

    // Get initial index
    // TODO: remove this
    // @ts-expect-error
    const initialIndex = this.tree[0]
      .map(arrayToBigInt)
      .indexOf(arrayToBigInt(element))
    let index = initialIndex

    if (index === -1) {
      throw new Error(
        `Couldn't find ${arrayToBigInt(element)} in the MerkleTree`
      )
    }

    // Loop through each level
    for (let level = 0; level < this.depth; level += 1) {
      if (index % 2 === 0) {
        // If index is even get element on right
        // TODO: remove this
        // @ts-expect-error
        elements.push(this.tree[level][index + 1] ?? this.zeros[level])
      } else {
        // If index is odd get element on left
        // TODO: remove this
        // @ts-expect-error
        elements.push(this.tree[level][index - 1])
      }

      // Get index for next level
      index = Math.floor(index / 2)
    }

    return {
      element,
      // TODO: remove this
      // @ts-expect-error
      elements,
      indices: initialIndex,
      root: this.root,
    }
  }

  /**
   * Validates a Merkle proof by reconstructing the root hash from the provided proof elements
   * and comparing it to the expected root hash.
   * @param proof - The Merkle proof object containing the indices, elements, and other necessary data.
   *                - `indices`: A binary representation indicating the position of each element in the proof.
   *                - `elements`: An array of hex-encoded strings representing the proof elements.
   * @returns `true` if the proof is valid and the reconstructed root matches the expected root; otherwise, `false`.
   */
  static validateProof (proof: MerkleProof): boolean {
    // Parse indices into binary string
    const indices = BigInt(proof.indices)
    // Initial currentHash value is the element we're proving membership for
    const calculatedRoot = proof.elements.reduce((current, element, index): Uint8Array => {
      // If index is right
      if ((indices & (2n ** BigInt(index))) > 0n) {
        return MerkleTree.hashLeftRight(element, current)
      }
      return MerkleTree.hashLeftRight(current, element)
    }, proof.element)

    return bytesToHex(proof.root) === bytesToHex(calculatedRoot)
  }
}

export type { MerkleProof }
export { MerkleTree }
