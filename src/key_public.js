const assert = require('assert');
const ecurve = require('ecurve');
const BigInteger = require('bigi');
const secp256k1 = ecurve.getCurveByName('secp256k1');

const hash = require('./hash');
const keyUtils = require('./key_utils');

var G = secp256k1.G
var n = secp256k1.n

module.exports = PublicKey

/**
  @param {string|Buffer|PublicKey|ecurve.Point} public key
  @param {string} [pubkey_prefix = 'RSN']
*/
function PublicKey(Q, pubkey_prefix = 'RSN') {
    if(typeof Q === 'string') {
        const publicKey = PublicKey.fromString(Q, pubkey_prefix)
        assert(publicKey != null, 'Invalid public key')
        return publicKey
    } else if(Buffer.isBuffer(Q)) {
        return PublicKey.fromBuffer(Q)
    } else if(typeof Q === 'object' && Q.Q) {
      return PublicKey(Q.Q)
    }

    assert.equal(typeof Q, 'object', 'Invalid public key')
    assert.equal(typeof Q.compressed, 'boolean', 'Invalid public key')

    function toBuffer(compressed = Q.compressed) {
        return Q.getEncoded(compressed);
    }

    let pubdata // cache

    // /**
    //     @todo secp224r1
    //     @return {string} PUB_K1_base58pubkey..
    // */
    // function toString() {
    //     if(pubdata) {
    //         return pubdata
    //     }
    //     pubdata = `PUB_K1_` + keyUtils.checkEncode(toBuffer(), 'K1')
    //     return pubdata;
    // }

    /** @todo rename to toStringLegacy
     * @arg {string} [pubkey_prefix = 'RSN'] - public key prefix
    */
    function toString(pubkey_prefix = 'RSN') {
      return pubkey_prefix + keyUtils.checkEncode(toBuffer())
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

    function toHex() {
        return toBuffer().toString('hex');
    }

    return {
        Q,
        toString,
        // toStringLegacy,
        toUncompressed,
        toBuffer,
        child,
        toHex
    }
}

/**
  @param {string|Buffer|PublicKey|ecurve.Point} pubkey - public key
  @param {string} [pubkey_prefix = 'RSN']
*/
PublicKey.isValid = function(pubkey, pubkey_prefix = 'RSN') {
    try {
        PublicKey(pubkey, pubkey_prefix)
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
    @arg {string} public_key - like PUB_K1_base58pubkey..
    @arg {string} [pubkey_prefix = 'RSN'] - public key prefix
    @return PublicKey or `null` (invalid)
*/
PublicKey.fromString = function(public_key, pubkey_prefix = 'RSN') {
    try {
        return PublicKey.fromStringOrThrow(public_key, pubkey_prefix)
    } catch (e) {
        return null;
    }
}

/**
    @arg {string} public_key - like PUB_K1_base58pubkey..
    @arg {string} [pubkey_prefix = 'RSN'] - public key prefix

    @throws {Error} if public key is invalid

    @return PublicKey
*/
PublicKey.fromStringOrThrow = function(public_key, pubkey_prefix = 'RSN') {
    assert.equal(typeof public_key, 'string', 'public_key')
    const match = public_key.match(/^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
    if(match === null) {
      // legacy
      var prefix_match = new RegExp("^" + pubkey_prefix);
      if(prefix_match.test(public_key)) {
        public_key = public_key.substring(pubkey_prefix.length)
      }
      return PublicKey.fromBuffer(keyUtils.checkDecode(public_key))
    }
    assert(match.length === 3, 'Expecting public key like: PUB_K1_base58pubkey..')
    const [, keyType, keyString] = match
    assert.equal(keyType, 'K1', 'K1 private key expected')
    return PublicKey.fromBuffer(keyUtils.checkDecode(keyString, keyType))
}

PublicKey.fromHex = function(hex) {
    return PublicKey.fromBuffer(new Buffer(hex, 'hex'));
}

PublicKey.fromStringHex = function(hex) {
    return PublicKey.fromString(new Buffer(hex, 'hex'));
}
