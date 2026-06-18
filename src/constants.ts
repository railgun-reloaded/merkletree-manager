import { bytesToBigInt } from '@railgun-reloaded/bytes'
import { keccak256 } from '@railgun-reloaded/cryptography'

import { SNARK_SCALAR_FIELD } from './bytes.js'

/**
 * Computes a zero value as a bigint by hashing the string "Railgun" using the keccak256 algorithm
 * and taking the result modulo the SNARK scalar field.
 * @returns The computed zero value as a bigint.
 */
const zeroValueBigInt = (): bigint => {
  const railgunHash = bytesToBigInt(
    keccak256(new Uint8Array(Buffer.from('Railgun', 'utf8')))
  )
  return railgunHash % SNARK_SCALAR_FIELD
}
// TODO: precompute some of these to use later.

const ZERO_HASH_BIGINT = zeroValueBigInt()

export { SNARK_SCALAR_FIELD, ZERO_HASH_BIGINT, zeroValueBigInt }
