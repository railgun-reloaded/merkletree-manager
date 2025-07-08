import { describe, it } from 'node:test'

import { poseidonFunc } from '@railgun-reloaded/cryptography'
// import assert from 'node:assert/strict'

describe('Importing cryptography library', () => {
  it('should hash poseidon', () => {
    poseidonFunc([0x1])
  })
})
