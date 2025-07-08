import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'

import { bytesToHex, hexToBytes } from '@railgun-reloaded/cryptography'

import { MerkleTree } from '../src'

describe('Importing library', () => {
  let testTree: MerkleTree
  before(() => {
    testTree = MerkleTree.createTree(0, 16)
  })
  it('should have the the ZERO root.', () => {
    assert(bytesToHex(testTree.root) === '14fceeac99eb8419a2796d1958fc2050d489bf5a3eb170ef16a667060344ba90')
  })

  it('should have the correct ZEROS array.', () => {
    const testVector = [
      '0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc',
      '01c405064436affeae1fc8e30b2e417b4243bbb819adca3b55bb32efc3e43a4f',
      '0888d37652d10d1781db54b70af87b42a2916e87118f507218f9a42a58e85ed2',
      '183f531ead7217ebc316b4c02a2aad5ad87a1d56d4fb9ed81bf84f644549eaf5',
      '093c48f1ecedf2baec231f0af848a57a76c6cf05b290a396707972e1defd17df',
      '1437bb465994e0453357c17a676b9fdba554e215795ebc17ea5012770dfb77c7',
      '12359ef9572912b49f44556b8bbbfa69318955352f54cfa35cb0f41309ed445a',
      '2dc656dadc82cf7a4707786f4d682b0f130b6515f7927bde48214d37ec25a46c',
      '2500bdfc1592791583acefd050bc439a87f1d8e8697eb773e8e69b44973e6fdc',
      '244ae3b19397e842778b254cd15c037ed49190141b288ff10eb1390b34dc2c31',
      '0ca2b107491c8ca6e5f7e22403ea8529c1e349a1057b8713e09ca9f5b9294d46',
      '18593c75a9e42af27b5e5b56b99c4c6a5d7e7d6e362f00c8e3f69aeebce52313',
      '17aca915b237b04f873518947a1f440f0c1477a6ac79299b3be46858137d4bfb',
      '2726c22ad3d9e23414887e8233ee83cc51603f58c48a9c9e33cb1f306d4365c0',
      '08c5bd0f85cef2f8c3c1412a2b69ee943c6925ecf79798bb2b84e1b76d26871f',
      '27f7c465045e0a4d8bec7c13e41d793734c50006ca08920732ce8c3096261435',
    ]
    assert.deepStrictEqual(testTree.zeros.map(bytesToHex), testVector)
    assert.deepStrictEqual(testTree.zeros, testVector.map(hexToBytes))
  })
})
