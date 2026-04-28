import { bigIntToBytes, bytesToBigInt } from '@railgun-reloaded/bytes'

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

const SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

export {
  SNARK_SCALAR_FIELD,
  railgunBase37,
}
