var ecdsa = require('./ecdsa');
var hash = require('./hash');
var curve = require('ecurve').getCurveByName('secp256k1');
var assert = require('assert');
var BigInteger = require('bigi');
var PublicKey = require('./key_public');
var PrivateKey = require('./key_private');

module.exports = Signature

function Signature(r, s, i) {
    assert.equal(r != null, true, 'Missing parameter');
    assert.equal(s != null, true, 'Missing parameter');
    assert.equal(i != null, true, 'Missing parameter');

    /**
        Verify signed data.

        @arg {String|Buffer} data - full data (non-hex)
        @arg {pubkey|PublicKey} pubkey - EOSKey..

        @return {boolean}
    */
    function verify(data, pubkey) {
        if(typeof data === 'string') {
            data = Buffer.from(data)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)
        return verifyHash(data, pubkey)
    }

    /**
        Verify a buffer of exactally 32 bytes in size (sha256(text))

        @arg {Buffer|hex} dataSha256 - 32 byte buffer or hex string
        @arg {String|PublicKey} pubkey

        @return {Signature}
    */
    function verifyHash(dataSha256, pubkey) {
        if(typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, 'hex')
        }
        if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256))
            throw new Error("dataSha256: 32 byte buffer requred")

        const publicKey = PublicKey(pubkey)
        assert(publicKey, 'pubkey required')

        return ecdsa.verify(
            curve, dataSha256,
            { r: r, s: s },
            publicKey.Q
        );
    };

    /** Verify hex data by converting to a buffer then hashing.
        @return {boolean}
    */
    function verifyHex(hex, pubkey) {
        const buf = Buffer.from(hex, 'hex');
        return verify(buf, pubkey);
    };

    /**
        Recover the public key used to create this signature using full data.
        
        @arg {String|Buffer} data - full data (non-hex)

        @return {PublicKey}
    */
    function recover(data) {
        if(typeof data === 'string') {
            data = Buffer.from(data)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)

        return recoverHash(data)
    };

    /**
        @arg {Buffer|hex} dataSha256 - 32 byte buffer or hex string
        @return {PublicKey}
    */
    function recoverHash(dataSha256) {
        if(typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, 'hex')
        }
        if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256)) {
            throw new Error("dataSha256: 32 byte String or buffer requred")
        }

        const e = BigInteger.fromBuffer(dataSha256);
        let i2 = i
        i2 -= 27;
        i2 = i2 & 3;
        const Q = ecdsa.recoverPubKey(curve, e, {r, s, i}, i2);
        return PublicKey.fromPoint(Q);
    };

    function toBuffer() {
        var buf;
        buf = new Buffer(65);
        buf.writeUInt8(i, 0);
        r.toBuffer(32).copy(buf, 1);
        s.toBuffer(32).copy(buf, 33);
        return buf;
    };

    function toHex() {
        return toBuffer().toString("hex");
    };

    return {
        r, s, i,
        toBuffer,
        verify,
        verifyHash,
        verifyHex,
        recover,
        recoverHash,
        toHex,

        /** @deprecated use verify (same arguments and return) */
        verifyBuffer: verify,

        /** @deprecated use recover (same arguments and return) */
        recoverPublicKey: recover,

        /** @deprecated use recoverHash (same arguments and return) */
        recoverPublicKeyFromBuffer: recoverHash,

    }
}

/**
    Hash and sign arbitrary data.

    @arg {string|Buffer} data - non-hex data
    @arg {wif|PrivateKey} privateKey

    @return {Signature}
*/
Signature.sign = function(data, privateKey) {
    if(typeof data === 'string') {
        data = Buffer.from(data)
    }
    assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
    data = hash.sha256(data)
    return Signature.signHash(data, privateKey)
}

/**
    Sign a buffer of exactally 32 bytes in size (sha256(text))

    @arg {Buffer|hex} buf - 32 byte buffer or hex string
    @arg {wif|PrivateKey} privateKey

    @return {Signature}
*/
Signature.signHash = function(dataSha256, privateKey) {
    if(typeof dataSha256 === 'string') {
        dataSha256 = Buffer.from(dataSha256, 'hex')
    }
    if( dataSha256.length !== 32 || ! Buffer.isBuffer(dataSha256) )
        throw new Error("dataSha256: 32 byte buffer requred")

    privateKey = PrivateKey(privateKey)
    assert(privateKey, 'privateKey required')

    var der, e, ecsignature, i, lenR, lenS, nonce;
    i = null;
    nonce = 0;
    e = BigInteger.fromBuffer(dataSha256);
    while (true) {
      ecsignature = ecdsa.sign(curve, dataSha256, privateKey.d, nonce++);
      der = ecsignature.toDER();
      lenR = der[3];
      lenS = der[5 + lenR];
      if (lenR === 32 && lenS === 32) {
        i = ecdsa.calcPubKeyRecoveryParam(curve, e, ecsignature, privateKey.toPublic().Q);
        i += 4;  // compressed
        i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
        break;
      }
      if (nonce % 10 === 0) {
        console.log("WARN: " + nonce + " attempts to find canonical signature");
      }
    }
    return Signature(ecsignature.r, ecsignature.s, i);
};

Signature.fromBuffer = function(buf) {
    var i, r, s;
    assert(Buffer.isBuffer(buf), 'Buffer is required')
    assert.equal(buf.length, 65, 'Invalid signature length');
    i = buf.readUInt8(0);
    assert.equal(i - 27, i - 27 & 7, 'Invalid signature parameter');
    r = BigInteger.fromBuffer(buf.slice(1, 33));
    s = BigInteger.fromBuffer(buf.slice(33));
    return Signature(r, s, i);
};

Signature.fromHex = function(hex) {
    return Signature.fromBuffer(Buffer.from(hex, "hex"));
};

/**
    @arg {String|Signature} o - hex string
    @return {Signature}
*/
Signature.from = o => {
    const signature = o ?
        (o.r && o.s && o.i) ? o :
        typeof o === 'string' ? Signature.fromHex(o) :
        Buffer.isBuffer(o) ? Signature.fromBuffer(o) :
        null : o/*null or undefined*/

    if(!signature) {
        throw new TypeError('signature should be a hex string or buffer')
    }
    return signature
}
