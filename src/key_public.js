const BigInteger = require('bigi');
const ecurve = require('ecurve');
const secp256k1 = ecurve.getCurveByName('secp256k1');
const base58 = require('bs58');
const hash = require('./hash');
const config = require('./config');
const assert = require('assert');

var G = secp256k1.G
var n = secp256k1.n

module.exports = PublicKey

/** @param {ecurve.Point} public key */
function PublicKey(Q) {

    if(typeof Q === 'string') {
        const publicKey = PublicKey.fromString(Q)
        assert(publicKey != null, 'Invalid public key')
        return publicKey
    } else if(Buffer.isBuffer(Q)) {
        return PublicKey.fromBuffer(Q)
    } else if(typeof Q === 'object' && Q.Q) {
      return PublicKey(Q.Q)
    }

    if(typeof Q !== 'object' || typeof Q.compressed !== 'boolean') {
        throw new TypeError('Invalid public key')
    }

    function toBuffer(compressed = Q.compressed) {
        return Q.getEncoded(compressed);
    }

    let pubdata // cache
    
    /**
        Full public key
        @return {string} EOSKey..
    */
    function toString(address_prefix = config.address_prefix) {
        if(pubdata) {
            return address_prefix + pubdata
        }
        const pub_buf = toBuffer();
        const checksum = hash.ripemd160(pub_buf);
        const addy = Buffer.concat([pub_buf, checksum.slice(0, 4)]);
        pubdata = base58.encode(addy)
        return address_prefix + pubdata;
    }

    function toUncompressed() {
        var buf = Q.getEncoded(false);
        var point = ecurve.Point.decodeFrom(secp256k1, buf);
        return PublicKey.fromPoint(point);
    }

    /** @deprecated */
    function child( offset ) {
        console.error('Deprecated warning: PublicKey.child')

        assert(Buffer.isBuffer(offset), "Buffer required: offset")
        assert.equal(offset.length, 32, "offset length")

        offset = Buffer.concat([ toBuffer(), offset ])
        offset = hash.sha256( offset )

        let c = BigInteger.fromBuffer( offset )

        if (c.compareTo(n) >= 0)
            throw new Error("Child offset went out of bounds, try again")


        let cG = G.multiply(c)
        let Qprime = Q.add(cG)

        if( secp256k1.isInfinity(Qprime) )
            throw new Error("Child offset derived to an invalid key, try again")

        return PublicKey.fromPoint(Qprime)
    }

    // toByteBuffer() {
    //     var b = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
    //     appendByteBuffer(b);
    //     return b.copy(0, b.offset);
    // }

    function toHex() {
        return toBuffer().toString('hex');
    }

    return {
        Q,
        toString,
        toUncompressed,
        toBuffer,
        child,
        toHex
    }
}

PublicKey.isValid = function(text) {
    try {
        PublicKey(text)
        return true
    } catch(e) {
        return false
    }
}

PublicKey.fromBinary = function(bin) {
    return PublicKey.fromBuffer(new Buffer(bin, 'binary'));
}

PublicKey.fromBuffer = function(buffer) {
    return PublicKey(ecurve.Point.decodeFrom(secp256k1, buffer));
}

PublicKey.fromPoint = function(point) {
    return PublicKey(point);
}

/**
    @arg {string} public_key - like STMXyz...
    @arg {string} address_prefix - like STM
    @return PublicKey or `null` (if the public_key string is invalid)
*/
PublicKey.fromString = function(public_key, address_prefix = config.address_prefix) {
    try {
        return PublicKey.fromStringOrThrow(public_key, address_prefix)
    } catch (e) {
        return null;
    }
}

/**
    @arg {string} public_key - like EOSKey..
    @arg {string} address_prefix - like EOS
    @throws {Error} if public key is invalid
    @return PublicKey
*/
PublicKey.fromStringOrThrow = function(public_key, address_prefix = config.address_prefix) {
    var prefix = public_key.slice(0, address_prefix.length);
    assert.equal(
        address_prefix, prefix,
        `Expecting key to begin with ${address_prefix}, instead got ${prefix}`);
        public_key = public_key.slice(address_prefix.length);

    public_key = new Buffer(base58.decode(public_key), 'binary');
    var checksum = public_key.slice(-4);
    public_key = public_key.slice(0, -4);
    var new_checksum = hash.ripemd160(public_key);
    new_checksum = new_checksum.slice(0, 4);
    assert.deepEqual(checksum, new_checksum,
      'Checksum did not match, ' +
      `${checksum.toString('hex')} != ${new_checksum.toString('hex')}`
    );
    return PublicKey.fromBuffer(public_key);
}

PublicKey.fromHex = function(hex) {
    return PublicKey.fromBuffer(new Buffer(hex, 'hex'));
}

PublicKey.fromStringHex = function(hex) {
    return PublicKey.fromString(new Buffer(hex, 'hex'));
}
