import {ABIEncoder, Bytes, Checksum256, KeyType, PublicKey, Signature} from '@greymass/eosio'
import {decode as cborDecode} from 'cborg'
import {ec} from 'elliptic'

import {Decoder} from './decoder'

export function createPublic(attestationResponse: {
    attestationObject: ArrayBuffer
    clientDataJSON: ArrayBuffer
}) {
    const clientData = decodeBinaryJson(attestationResponse.clientDataJSON)
    const origin = clientData.origin
    if (typeof origin !== 'string') {
        throw new Error('Missing origin in client data')
    }
    const originUrl = new URL(origin)
    if (originUrl.protocol !== 'https:') {
        throw new Error('WebAuthn keys require https')
    }

    const attestationObject = cborDecode(new Uint8Array(attestationResponse.attestationObject))
    if (!(attestationObject.authData instanceof Uint8Array)) {
        throw new Error('Missing auth data')
    }

    const authData = decodeAuthData(attestationObject.authData)
    const ecPoint = getECPoint(authData.credentialPublicKey)

    const compressed = new Uint8Array(33)
    compressed[0] = ecPoint.y[31] & 0x01 ? 0x03 : 0x02
    compressed.set(ecPoint.x, 1)

    const abiEncoder = new ABIEncoder()
    abiEncoder.writeArray(compressed)
    if (authData.flags & 0x01 /* user present */) {
        abiEncoder.writeByte(0x02)
    } else if (authData.flags & 0x04 /* user verified */) {
        abiEncoder.writeByte(0x02)
    } else {
        abiEncoder.writeByte(0x00)
    }
    abiEncoder.writeString(originUrl.hostname)

    return new PublicKey(KeyType.WA, abiEncoder.getBytes())
}

export function createSignature(
    publicKey: PublicKey,
    assertionResponse: {
        signature: ArrayBuffer
        authenticatorData: ArrayBuffer
        clientDataJSON: ArrayBuffer
    }
) {
    const decoder = new Decoder(assertionResponse.signature).derDecoder(0x30)
    const r = fixPoint(decoder.readDer(0x02))
    const s = fixPoint(decoder.readDer(0x02))

    const authenticatorData = Bytes.from(assertionResponse.authenticatorData)
    const clientDataJSON = Bytes.from(assertionResponse.clientDataJSON)

    const message = new Bytes()
    message.append(authenticatorData)
    message.append(Checksum256.hash(clientDataJSON))

    const curve = new ec('p256')
    const pk = curve.keyFromPublic(publicKey.data.array.slice(0, 33)).getPublic()
    const m = Checksum256.hash(message).array
    const recid = (curve.getKeyRecoveryParam as any)(m, {r, s}, pk)

    const encoder = new ABIEncoder()
    encoder.writeByte(recid + 31)
    encoder.writeArray(r)
    encoder.writeArray(s)
    authenticatorData.toABI(encoder)
    clientDataJSON.toABI(encoder)

    return new Signature(KeyType.WA, encoder.getBytes())
}

function decodeAuthData(authData: Uint8Array) {
    const decoder = new Decoder(authData)

    const rpIdHash = decoder.readArray(32)
    const flags = decoder.readByte()
    const counter = decoder.readNum(4)
    const aaguid = decoder.readArray(16)
    const credentialId = decoder.readArray(decoder.readNum(2))
    const credentialPublicKey = cborDecode(decoder.remainder(), {useMaps: true}) as Map<number, any>

    return {
        rpIdHash,
        flags,
        counter,
        aaguid,
        credentialId,
        credentialPublicKey,
    }
}

function getECPoint(credentialPublicKey: Map<number, any>) {
    const kty = credentialPublicKey.get(1)
    if (kty !== 2 /* EC */) {
        throw new Error(`Unsupported key type: ${kty}`)
    }
    const alg = credentialPublicKey.get(3)
    if (alg !== -7 /* EC2 */) {
        throw new Error(`Unsupported key algorithm: ${alg}`)
    }
    const crv = credentialPublicKey.get(-1)
    if (crv !== 1 /*P-256*/) {
        throw new Error(`Unsupported ec key curve: ${crv}`)
    }
    const x = credentialPublicKey.get(-2)
    const y = credentialPublicKey.get(-3)
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
        throw new Error('Invalid public key data')
    }
    return {x, y}
}

function decodeBinaryJson(data: ArrayBuffer) {
    const decoder = new TextDecoder()
    return JSON.parse(decoder.decode(data))
}

// chrome sometimes returns curve points that are not 32 bytes, so we need to make sure they are
function fixPoint(x: Uint8Array) {
    if (x.length === 32) {
        return x
    }
    const rv = new Uint8Array(32)
    rv.fill(0)
    let si = 0
    while (x[si] === 0 && si < x.length - 1) {
        si++
    }
    rv.set(x.slice(si), 32 - x.length + si)
    return rv
}
