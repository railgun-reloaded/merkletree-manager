import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'

import { bytesToHex, hexToBytes } from '@railgun-reloaded/cryptography'

import { MerkleTree } from '../src'

describe('Importing library', () => {
  let testTree: MerkleTree
  beforeEach(() => {
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

  it('should hash left/right.', () => {
    const vectors = [
      {
        left: '115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',
        right: '2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b',
        result: '106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3',
      },
      {
        left: '0db945439b762ad08f144bcccc3746773b332e8a0045a11d87662dc227923df5',
        right: '09ce612d20912e20cde93cd2a03fcccdfdce5910242b555ff35b5373041bf329',
        result: '063c1c7dfb4b63255c492bb6b32d57eddddcb1c78cfb990e7b35416cf966ed79',
      },
      {
        left: '09cf3efaeb0190e482c9f9cf1534f17fbf0ed1537c26db9faf26f3d55140804d',
        right: '2651021f2d224338f1c9f408db74111c98e7381072b9fcd640bd4f748584e769',
        result: '1576a4dd906cab90e381775c1c9bb1d713f7f02c7ec0911a8bc38a1c4b0bf69e',
      },
    ]

    for (const vector of vectors) {
      const bytes = MerkleTree.hashLeftRight(hexToBytes(vector.left), hexToBytes(vector.right))
      assert(bytesToHex(bytes) === vector.result)
    }
  })
  it('should update merkle tree correctly.', () => {
    const vectors = [
      '02',
      '04',
      '08',
      '10',
      '20',
      '40',
    ]
    testTree.insertLeaves(vectors.map(hexToBytes), 0)
    testTree.rebuildSparseTree()
    const proof = testTree.generateProof(hexToBytes('10'))

    const formatted = {
      element: bytesToHex(proof.element),
      elements: proof.elements.map(bytesToHex),
      indices: proof.indices,
      root: bytesToHex(proof.root)
    }
    assert.deepStrictEqual(formatted, {
      element: '10',
      elements: [
        '08',
        '022678592fe7f282774b001df184b9448e46f7bc5b4d879f7f545a09f6e77feb',
        '071f842dbbae18082c04bfd08f4a56d71e1444317bfc6417dae8ac604d9493de',
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
      ],
      indices: 3,
      root: '215b6e027da417c086db7e55d19c6d2cc270a0c2d54a2b2cd9ae8d40d0c250b3',
    })
  })
})
