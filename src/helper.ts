import type { MerkleProof } from './index'
import { MerkleTree } from './index'

/**
 * The `MerkleHelper` class is designed to manage multiple Merkle trees, providing functionality
 * for efficient insertion of leaves, tree finalization, proof generation, and retrieval of tree properties.
 * Merkle trees are cryptographic structures used for secure and efficient verification of data integrity.
 *
 * ### Features:
 * - **Tree Management**: Handles multiple Merkle trees, allowing for dynamic creation of new trees when the current one is full.
 * - **Leaf Insertion**: Inserts leaves into the appropriate tree, automatically creating new trees as needed.
 * - **Proof Generation**: Generates cryptographic proofs for elements in any of the managed trees.
 * - **Tree Finalization**: Optimizes the current tree by rebuilding its sparse representation.
 * - **Property Access**: Provides access to tree roots, depth, and other properties.
 *
 * ### Usage:
 * 1. Instantiate the `MerkleHelper` class with a specified tree depth.
 * 2. Use `insertLeaves` to add data to the trees.
 * 3. Call `finalizeTree` to optimize the current tree.
 * 4. Use `generateProof` to retrieve cryptographic proofs for data verification.
 * 5. Access tree properties such as `roots`, `root`, and `depth` for additional information.
 *
 * ### Example:
 * ```typescript
 * const merkleHelper = new MerkleHelper(16);
 * const leaves = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
 * merkleHelper.insertLeaves(leaves, 0);
 * const proof = merkleHelper.generateProof(new Uint8Array([1, 2, 3]));
 * console.log(proof);
 */
export class MerkleHelper {
  /**
   * An array of MerkleTree instances managed by this class.
   * Each MerkleTree represents a cryptographic structure used for efficient and secure verification of data.
   */
  trees: MerkleTree[] = []
  /**
   * Represents the index of the current Merkle tree being managed.
   * This value is used to track and reference the active tree within the system.
   */
  currentTreeIndex = 0
  /**
   * The maximum number of leaves that the Merkle tree can contain.
   * This property defines the upper limit for the number of elements
   * that can be added to the tree.
   */
  readonly maxLeaves: number
  /**
   * Represents the depth of the Merkle tree.
   * The tree depth determines the number of levels in the tree,
   * starting from the leaf nodes up to the root.
   */
  readonly treeDepth: number

  /**
   * Creates a new MerkleHelper to manage multiple trees
   * @param treeDepth - The depth of each merkle tree (default: 16)
   */
  constructor (treeDepth = 16) {
    this.treeDepth = treeDepth
    this.maxLeaves = 2 ** treeDepth
    const firstTree = MerkleTree.createTree(0, this.treeDepth)
    this.trees.push(firstTree)
  }

  /**
   * Gets the current active tree
   * @returns The current merkle tree
   */
  get currentTree (): MerkleTree {
    const tree = this.trees[this.currentTreeIndex]
    if (!tree) {
      throw new Error('Current tree is undefined')
    }
    return tree
  }

  /**
   * Creates a new tree when the current one is full
   * be sure to call finalizeTree() before this
   */
  private createNextTree (): void {
    const nextTreeNumber = this.trees.length
    const newTree = MerkleTree.createTree(
      nextTreeNumber,
      this.treeDepth,
      this.currentTree
    )
    this.trees.push(newTree)
    this.currentTreeIndex = nextTreeNumber
  }

  /**
   * Inserts leaves into the appropriate tree, creating a new one if needed
   * @param leaves - Array of leaves to insert
   * @param startPosition - Leaf Index to start adding leaves from.
   * @returns The tree index where leaves were inserted
   */
  insertLeaves (
    leaves: Uint8Array[],
    startPosition: number
  ): number {
    if (leaves.length === 0) return this.currentTreeIndex

    // Insert leaves into the current tree
    // Check if startPosition is valid
    if (startPosition < 0 || startPosition >= this.maxLeaves) {
      console.log(startPosition, this.maxLeaves)
      throw new Error('Invalid start position')
    }
    // Check if start position matches the current tree length
    if (startPosition !== this.currentTree.length) {
      console.log(startPosition, this.currentTree.length)
      throw new Error('Start position does not match current tree length')
    }

    // Check if current tree has enough space
    if (this.currentTree.length + leaves.length > this.maxLeaves) {
      // Get the number of leaves that can be added to the current tree
      const remainingLeaves = this.maxLeaves - this.currentTree.length
      // If there are remaining leaves, insert them
      if (remainingLeaves > 0) {
        const leavesToInsert = leaves.slice(0, remainingLeaves)
        this.currentTree.insertLeaves(leavesToInsert, startPosition)
      }
      console.log('CREATING NEW TREE')
      // Remove the inserted leaves from the original array
      const newLeaves = leaves.slice(remainingLeaves)
      //  Create a new tree
      // Rebuild current tree first
      this.finalizeTree()
      this.createNextTree()
      // Insert the remaining leaves into the new tree
      this.currentTree.insertLeaves(newLeaves, 0)
    } else {
      // Business as usual
      this.currentTree.insertLeaves(leaves, startPosition)
    }

    // await this.finalizeTree();

    return this.currentTreeIndex
  }

  /**
   * Finalizes the current Merkle tree by rebuilding its sparse representation.
   * This method measures and logs the time taken to rebuild the sparse tree.
   * It is intended to optimize the tree structure for efficient operations.
   * The `rebuildSparseTree` method is called on the `currentTree` instance
   * to perform the rebuilding process.
   */
  finalizeTree (): void {
    console.time('Rebuilding sparse tree')
    this.currentTree.rebuildSparseTree()
    console.timeEnd('Rebuilding sparse tree')
  }

  /**
   * Generates a proof for an element in any of the managed trees
   * @param element - Element to find and generate proof for
   * @param treeIndex - Optional specific tree index to search in
   * @returns The merkle proof and the tree index
   */
  generateProof (
    element: Uint8Array,
    treeIndex?: number
  ): { proof: MerkleProof; treeIndex: number } {
    if (
      treeIndex !== undefined &&
      this.trees[treeIndex] &&
      treeIndex >= 0 &&
      treeIndex < this.trees.length
    ) {
      // If tree index is specified, generate proof from that tree
      return {
        proof: this.trees[treeIndex].generateProof(element),
        treeIndex,
      }
    }

    // Search in all trees
    for (let i = 0; i < this.trees.length; i++) {
      try {
        if (typeof this.trees[i] === 'undefined') {
          throw new Error('Tree not found')
        }
        const tree = this.trees[i]
        if (!tree) {
          throw new Error('Tree not found')
        }
        const proof = tree.generateProof(element)
        return { proof, treeIndex: i }
      } catch (error) {
        // Element not found in this tree, continue searching
      }
    }

    throw new Error('Element not found in any tree')
  }

  /**
   * Gets the roots of all trees
   * @returns Array of tree roots
   */
  get roots (): Uint8Array[] {
    return this.trees.map((tree) => tree.root)
  }

  /**
   * Retrieves the root of the current Merkle tree.
   * @returns  The root hash of the current Merkle tree.
   */
  get root (): Uint8Array {
    return this.currentTree.root
  }

  /**
   * Gets the depth of the current Merkle tree.
   * The depth represents the number of levels in the tree,
   * starting from the leaves up to the root.
   * @returns  The depth of the current Merkle tree.
   */
  get depth (): number {
    return this.currentTree.depth
  }
}
