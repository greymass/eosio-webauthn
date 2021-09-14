export class Decoder {
    private pos = 0
    private data: DataView
    private array: Uint8Array

    constructor(data: Uint8Array | ArrayBuffer) {
        if (data instanceof Uint8Array) {
            this.data = new DataView(data.buffer, data.byteOffset, data.byteLength)
            this.array = data
        } else {
            this.data = new DataView(data)
            this.array = new Uint8Array(data)
        }
    }

    canRead(bytes = 1): boolean {
        return !(this.pos + bytes > this.array.byteLength)
    }

    private ensure(bytes: number) {
        if (!this.canRead(bytes)) {
            throw new Error('Read past end of buffer')
        }
    }

    /** Read one byte. */
    readByte(): number {
        this.ensure(1)
        return this.array[this.pos++]
    }

    /** Read integer as JavaScript number, up to 32 bits. */
    readNum(byteWidth: number, littleEndian = false) {
        this.ensure(byteWidth)
        const d = this.data,
            p = this.pos
        let rv: number
        switch (byteWidth) {
            case 1:
                rv = d.getUint8(p)
                break
            case 2:
                rv = d.getUint16(p, littleEndian)
                break
            case 4:
                rv = d.getUint32(p, littleEndian)
                break
            case -1:
                rv = d.getInt8(p)
                break
            case -2:
                rv = d.getInt16(p, littleEndian)
                break
            case -4:
                rv = d.getInt32(p, littleEndian)
                break
            default:
                throw new Error('Invalid integer width')
        }
        this.pos += byteWidth
        return rv
    }

    readArray(length: number) {
        this.ensure(length)
        const rv = this.array.subarray(this.pos, this.pos + length)
        this.pos += length
        return rv
    }

    remainder() {
        return this.array.subarray(this.pos)
    }

    readDer(tag: number) {
        const t = this.readByte()
        if (t !== tag) {
            throw new Error(`Unexpected DER tag: ${t}`)
        }
        const len = this.readByte()
        if (len < 0) {
            throw new Error('Invalid DER length')
        }

        return this.readArray(len)
    }

    derDecoder(tag: number) {
        return new Decoder(this.readDer(tag))
    }
}
