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
    // Initialize output in base10
    let outputNumber = 0n

    // Calculate number system base
    const base = BigInt(railgunBase37.CHARSET.length)

    // Loop through each char from least significant to most
    for (let i = 0; i < text.length; i += 1) {
      // Get decimal value of char
      const charIndex = railgunBase37.CHARSET.indexOf(text[i]!)

      // Throw if char is invalid
      if (charIndex === -1) throw new Error(`Invalid character: ${text[i]}`)

      // Calculate positional multiplier for char
      const positional = base ** BigInt(text.length - i - 1)

      // Add char value to decimal
      outputNumber += BigInt(charIndex) * positional
    }

    // Convert base 10 to 16 byte array
    return bigIntToBytes(outputNumber, 16)
  },

  /**
   * Decodes RAILGUN base-37 encoded bytes back into text.
   * @param bytes - Encoded bytes to decode.
   * @returns Decoded text.
   */
  decode (bytes: Uint8Array): string {
    // Initialize output string
    let output = ''

    // Convert input to number
    let inputNumber = bytesToBigInt(bytes)

    // Calculate number system base
    const base = BigInt(railgunBase37.CHARSET.length)

    // Loop through input number it is the last positional
    while (inputNumber > 0) {
      // Calculate last positional value
      const remainder = inputNumber % base

      // Add last positional value to start of string
      output = `${railgunBase37.CHARSET[Number(remainder)]}${output}`

      // Subtract last positional value and shift right 1 position
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
