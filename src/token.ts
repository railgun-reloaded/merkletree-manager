import { arrayToBigInt, keccak256, poseidonFunc } from '@railgun-reloaded/cryptography'

import { SNARK_SCALAR_FIELD, arrayToByteLength, bigIntToArray, combine, hexStringToArray, padToLength } from './bytes'
import type { TokenData } from './types'
import { TokenType } from './types'

/**
 * Computes the token ID for a given TokenData object.
 *
 * For ERC20 tokens, the token ID is simply the token address padded to 32 bytes.
 * For other token types, the token ID is calculated as the keccak256 hash of the
 * concatenated tokenType, tokenAddress (padded to 32 bytes), and tokenSubID,
 * with the result being taken modulo the SNARK scalar field.
 * @param tokenData - The token data containing tokenType, tokenAddress, and potentially tokenSubID
 * @returns A Uint8Array of 32 bytes representing the token ID
 */
const getTokenID = (tokenData: TokenData): Uint8Array => {
  // ERC20 tokenID is just the address
  if (tokenData.tokenType === TokenType.ERC20) {
    return arrayToByteLength(hexStringToArray(tokenData.tokenAddress), 32)
  }

  // Other token types are the keccak256 hash of the token data
  return bigIntToArray(
    arrayToBigInt(
      keccak256(
        combine([
          bigIntToArray(BigInt(tokenData.tokenType), 32),
          padToLength(hexStringToArray(tokenData.tokenAddress), 32, 'left'),
          arrayToByteLength(hexStringToArray(tokenData.tokenSubID), 32),
        ])
      )
    ) % SNARK_SCALAR_FIELD,
    32
  )
}

/**
 * Generates a commitment leaf using the provided note public key (npk), token data, and value.
 * @param npk - A Uint8Array representing the note public key.
 * @param tokenData - An object containing token-related data used to derive the token ID.
 * @param value - A Uint8Array representing the value to be included in the commitment leaf.
 * @returns A Uint8Array representing the computed commitment leaf using the Poseidon hash function.
 * - The `value` is padded to a length of 32 bytes on the left before hashing.
 * - The `getTokenID` function extracts the token ID from the provided `tokenData`.
 */
const getCommitmentLeaf = (
  npk: Uint8Array,
  tokenData: TokenData,
  value: Uint8Array
) => {
  const npkArray = npk
  const tokenID = getTokenID(tokenData)
  const valueArray = padToLength(value, 32, 'left')
  // @ts-expect-error - this needs to be fixed, uint8Array are applicable
  return poseidonFunc([npkArray, tokenID, valueArray])
}

export { getCommitmentLeaf, getTokenID }
