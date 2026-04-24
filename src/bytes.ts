import { bigIntToBytes, bytesToBigInt } from '@railgun-reloaded/bytes'

/**
 * Left-pads a byte array to the requested length. Throws if the input is
 * already longer than the target length (unlike
 * `@railgun-reloaded/bytes#padBytesLeft`, which returns the input unchanged
 * when it is already at or above the target).
 * @param byteArray - Byte array to pad.
 * @param length - Target length in bytes.
 * @returns Byte array of exactly `length` bytes, zero-padded on the left.
 * @throws If `byteArray.length > length`.
 */
const arrayToByteLength = (byteArray: Uint8Array, length: number): Uint8Array => {
  if (byteArray.length > length) { throw new Error('BigInt byte size is larger than length') }

  return new Uint8Array(
    new Array(length - byteArray.length).concat(...byteArray)
  )
}

/**
 * Splits a byte array into fixed-size chunks.
 * @param data - Byte array to split.
 * @param size - Chunk size in bytes.
 * @returns Array of chunk byte arrays. The final chunk may be shorter than
 * `size` if `data.length` is not a multiple of `size`.
 */
const chunk = (data: Uint8Array, size: number): Uint8Array[] => {
  const chunks: Uint8Array[] = []

  for (let i = 0; i < data.length; i += size) {
    chunks.push(data.slice(i, i + size))
  }

  return chunks
}

/**
 * Concatenates a list of byte arrays end-to-end.
 * @param chunks - Byte arrays to concatenate.
 * @returns A single byte array containing every input in order.
 */
const combine = (chunks: Uint8Array[]): Uint8Array => {
  return chunks.reduce((left, right) => new Uint8Array([...left, ...right]))
}

/**
 * Pads a byte array to a target length by adding zero bytes on the specified side.
 * @param data - Byte array to pad.
 * @param length - Target length in bytes; must be greater than or equal to `data.length`.
 * @param side - Side to pad on.
 * @returns Byte array of exactly `length` bytes.
 */
const padToLength = (
  data: Uint8Array,
  length: number,
  side: 'left' | 'right'
): Uint8Array => {
  const slack = length - data.length

  if (side === 'left') {
    return new Uint8Array([...new Uint8Array(slack), ...data])
  } else {
    return new Uint8Array([...data, ...new Uint8Array(slack)])
  }
}

const railgunBase37 = {
  CHARSET: ' 0123456789abcdefghijklmnopqrstuvwxyz',

  /**
   * Encodes text as a 16-byte big-endian integer using RAILGUN's base-37 charset.
   * @param text - Text to encode. Each character must be present in `CHARSET`.
   * @returns 16-byte encoded value.
   * @throws If `text` contains a character not in `CHARSET`.
   */
  encode (text: string): Uint8Array {
    let outputNumber = 0n

    const base = BigInt(railgunBase37.CHARSET.length)

    for (let i = 0; i < text.length; i += 1) {
      const charIndex = railgunBase37.CHARSET.indexOf(text[i]!)

      if (charIndex === -1) throw new Error(`Invalid character: ${text[i]}`)

      const positional = base ** BigInt(text.length - i - 1)

      outputNumber += BigInt(charIndex) * positional
    }

    return bigIntToBytes(outputNumber, 16)
  },

  /**
   * Decodes RAILGUN base-37 encoded bytes back into text.
   * @param bytes - Encoded bytes to decode.
   * @returns Decoded text.
   */
  decode (bytes: Uint8Array): string {
    let output = ''

    let inputNumber = bytesToBigInt(bytes)

    const base = BigInt(railgunBase37.CHARSET.length)

    while (inputNumber > 0) {
      const remainder = inputNumber % base

      output = `${railgunBase37.CHARSET[Number(remainder)]}${output}`

      inputNumber = (inputNumber - remainder) / base
    }

    return output
  },
}

/**
 * Decodes UTF-8 bytes into a string.
 * @param data - Byte array to decode.
 * @returns The decoded UTF-8 string.
 */
const toUTF8String = (data: Uint8Array): string => {
  return new TextDecoder().decode(data)
}

/**
 * Encodes a string as UTF-8 bytes.
 * @param string - String to encode.
 * @returns The UTF-8 encoded byte array.
 */
const fromUTF8String = (string: string): Uint8Array => {
  return new TextEncoder().encode(string)
}

const SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

export {
  SNARK_SCALAR_FIELD,
  arrayToByteLength,
  chunk,
  combine,
  fromUTF8String,
  padToLength,
  railgunBase37,
  toUTF8String,
}
