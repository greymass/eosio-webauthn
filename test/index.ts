import {assert} from 'chai'
import {Bytes, PublicKey} from '@greymass/eosio'

import * as lib from '$lib'

suite('index', function () {
    this.timeout(5000)
    this.slow(1000)

    test('createPublic', function () {
        const response = {
            attestationObject: Bytes.from(
                'a363666d74646e6f6e656761747453746d74a068617574684461746158980511e9517abcfeaa5db71dddb8ba831' +
                    'd0513ecdb1bd5f5907421ffa5c909ea3045000000000000000000000000000000000000000000149e093bb39d81' +
                    'de544b40af3fd3894c9a6d5214eba5010203262001215820d9eee421c986d509f9e575c08f4a3ab45bca6896a69' +
                    'fb4e83379a8bc9fb6af982258202ddb029af756c10243446b888892d91f82e63c101d5715308cb0155900ec862f'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                '7b2274797065223a22776562617574686e2e637265617465222c2263' +
                    '68616c6c656e6765223a2276755f367a694b2d375f724f76755f367a' +
                    '7237762d73346976755f367a7237762d7334222c226f726967696e22' +
                    '3a2268747470733a2f2f79656c6c6f776167656e74732e636f6d227d'
            ).array.buffer,
        }

        const key = lib.createPublic(response)
        assert.equal(
            key,
            'PUB_WA_2NVXH8vKM57G6raNdktPvTuMxBM9EeuK8uquDGhaXPfMV7SMFd4dUgza7xGStLnVJs5Xdhhm5fs'
        )
    })

    test('createSignature', function () {
        const response = {
            authenticatorData: Bytes.from(
                '0511e9517abcfeaa5db71dddb8ba831d0513ecdb1bd5f5907421ffa5c909ea300500000000'
            ).array.buffer,
            signature: Bytes.from(
                '3044022047ef146e8708bdcc0b7a92fc01685b0b37f522c313972b71fe988d7b0c69cd' +
                    '7d02206453d15bb8f566a3d2285877a7e681c6b8b5c610290e45026bbe091e99aadb9a'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b49222c226f726967696e223a2268747470733a2f2f79656c6c6f776167656e74732e636f6d227d'
            ).array.buffer,
        }
        const sig = lib.createSignature(
            PublicKey.from(
                'PUB_WA_2NVXH8vKM57G6raNdktPvTuMxBM9EeuK8uquDGhaXPfMV7SMFd4dUgza7xGStLnVJs5Xdhhm5fs'
            ),
            response
        )
        assert.equal(
            sig,
            'SIG_WA_PAmH7fjMVadx19QK8jQooKFsL8szj81CFMPAfAuZ9GkSPQczccCEVCuMKAFS9YP7CvkmzXYULYxvdBMx3Chi9Ld2tPkvtbC6TEYY3QS7fDmZLBQjPCatUncLQneG97KMPCohZzuUyTzr1ojbufyBJ65BNRrYSVQynzcJoVXuym8DLhm5HZf23UdKmb79rGCYkwP4xWeEgowarGmnnxvMsjfRxTrQHeh67TMKiVkz8r8unHh7Zkf5jTPVsKXjSTjEYuwj4aBWpSEXkVvYcWZ3wbSKs9gHjKjY8m22Qeye45D1NQe7vKR'
        )
    })
})
