const ecurve = require('ecurve');
const Point = ecurve.Point;
const secp256k1 = ecurve.getCurveByName('secp256k1');
const BigInteger = require('bigi');
const base58 = require('bs58');
const assert = require('assert');

const hash = require('./hash');
const PublicKey = require('./key_public');
const keyUtils = require('./key_utils');
const createHash = require('create-hash')
const promiseAsync = require('./promise-async')

const G = secp256k1.G
const n = secp256k1.n

module.exports = PrivateKey;

/**
  @typedef {string} wif - https://en.bitcoin.it/wiki/Wallet_import_format
  @typedef {string} pubkey - EOSKey..
  @typedef {ecurve.Point} Point
*/

/**
  @param {BigInteger} d
*/
function PrivateKey(d) {

    if(typeof d === 'string') {
        return PrivateKey.fromWif(d)
    } else if(Buffer.isBuffer(d)) {
        return PrivateKey.fromBuffer(d)
    } else if(typeof d === 'object' && BigInteger.isBigInteger(d.d)) {
        return PrivateKey(d.d)
    }

    if(!BigInteger.isBigInteger(d)) {
        throw new TypeError('Invalid private key')
    }

    /**
        @return  {wif}
    */
    function toWif() {
        var private_key = toBuffer();
        // checksum includes the version
        private_key = Buffer.concat([new Buffer([0x80]), private_key]);
        var checksum = hash.sha256(private_key);
        checksum = hash.sha256(checksum);
        checksum = checksum.slice(0, 4);
        var private_wif = Buffer.concat([private_key, checksum]);
        return base58.encode(private_wif);
    }

    let public_key;

    /**
        @return {Point}
    */
    function toPublic() {
        if (public_key) {
            // Hundreds of keys can be S L O W in the browser
            // cache
            return public_key
        }
        const Q = secp256k1.G.multiply(d);
        return public_key = PublicKey.fromPoint(Q);
    }

    function toBuffer() {
        return d.toBuffer(32);
    }

    /**
      ECIES
      @arg {string|Object} pubkey wif, PublicKey object
      @return {Buffer} 64 byte shared secret
    */
    function getSharedSecret(public_key) {
        public_key = PublicKey(public_key)
        let KB = public_key.toUncompressed().toBuffer()
        let KBP = Point.fromAffine(
          secp256k1,
          BigInteger.fromBuffer( KB.slice( 1,33 )), // x
          BigInteger.fromBuffer( KB.slice( 33,65 )) // y
        )
        let r = toBuffer()
        let P = KBP.multiply(BigInteger.fromBuffer(r))
        let S = P.affineX.toBuffer({size: 32})
        // SHA512 used in ECIES
        return hash.sha512(S)
    }

    // /** ECIES TODO unit test
    //   @arg {string|Object} pubkey wif, PublicKey object
    //   @return {Buffer} 64 byte shared secret
    // */
    // function getSharedSecret(public_key) {
    //     public_key = PublicKey(public_key).toUncompressed()
    //     var P = public_key.Q.multiply( d );
    //     var S = P.affineX.toBuffer({size: 32});
    //     // ECIES, adds an extra sha512
    //     return hash.sha512(S);
    // }

    /**
      @arg {string} name - child key name.
      @return {PrivateKey}

      @example activePrivate = masterPrivate.getChildKey('owner').getChildKey('active')
      @example activePrivate.getChildKey('mycontract').getChildKey('myperm')
    */
    function getChildKey(name) {
      // console.error('WARNING: getChildKey untested against eosd'); // no eosd impl yet
      const index = createHash('sha256').update(toBuffer()).update(name).digest()
      return PrivateKey(index)
    }

    function toHex() {
        return toBuffer().toString('hex');
    }

    return {
        d,
        toWif,
        toPublic,
        toBuffer,
        toString: toWif,
        getSharedSecret,
        getChildKey
    }
}

PrivateKey.fromHex = function(hex) {
    return PrivateKey.fromBuffer(new Buffer(hex, 'hex'));
}

PrivateKey.fromBuffer = function(buf) {
    if (!Buffer.isBuffer(buf)) {
        throw new Error("Expecting parameter to be a Buffer type");
    }
    if (32 !== buf.length) {
        console.log(`WARN: Expecting 32 bytes, instead got ${buf.length}, stack trace:`, new Error().stack);
    }
    if (buf.length === 0) {
        throw new Error("Empty buffer");
    }
    return PrivateKey(BigInteger.fromBuffer(buf));
}

/**
    @arg {string} seed - any length string.  This is private, the same seed
    produces the same private key every time.

    @return {PrivateKey}
*/
PrivateKey.fromSeed = function(seed) { // generate_private_key
    if (!(typeof seed === 'string')) {
        throw new Error('seed must be of type string');
    }
    return PrivateKey.fromBuffer(hash.sha256(seed));
}

PrivateKey.isWif = function(text) {
    try {
        PrivateKey.fromWif(text)
        return true
    } catch(e) {
        return false
    }
}

/**
  @arg {wif|Buffer|PrivateKey} key
  @return {boolean} true if key is convertable to a private key object.
*/
PrivateKey.isValid = function(key) {
    try {
        PrivateKey(key)
        return true
    } catch(e) {
        return false
    }
}

/**
    @throws {AssertError|Error} parsing key
    @return {string} Wallet Import Format (still a secret, Not encrypted)
*/
PrivateKey.fromWif = function(_private_wif) {
    var private_wif = new Buffer(base58.decode(_private_wif));
    var version = private_wif.readUInt8(0);
    assert.equal(0x80, version, `Expected version ${0x80}, instead got ${version}`);
    // checksum includes the version
    var private_key = private_wif.slice(0, -4);
    var checksum = private_wif.slice(-4);
    var new_checksum = hash.sha256(private_key);
    new_checksum = hash.sha256(new_checksum);
    new_checksum = new_checksum.slice(0, 4);
    if (checksum.toString() !== new_checksum.toString())
        throw new Error('Invalid WIF key (checksum miss-match), ' +
          `${checksum.toString('hex')} != ${new_checksum.toString('hex')}`
        )

    private_key = private_key.slice(1);
    return PrivateKey.fromBuffer(private_key);
}

/**
  Create a new random private key.

  Call initialize() first to run some self-checking code and gather some CPU
  entropy.

  @arg {number} [cpuEntropyBits = 0] - additional CPU entropy, this already
  happens once so it should not be needed again.

  @return {Promise<PrivateKey>} - random private key
*/
PrivateKey.randomKey = function(cpuEntropyBits = 0) {
  return PrivateKey.initialize().then(() => (
    PrivateKey.fromBuffer(keyUtils.random32ByteBuffer({cpuEntropyBits}))
  ))
}

/**
  @return {Promise<PrivateKey>} for testing, does not require initialize().
*/
PrivateKey.unsafeRandomKey = function() {
  return PrivateKey.initialize().then(() => (
    PrivateKey.fromBuffer(keyUtils.random32ByteBuffer({safe: false}))
  ))
}


let initialized = false, unitTested = false

/**
  Run self-checking code and gather CPU entropy.

  Initialization happens once even if called multiple times.

  @return {Promise}
*/
function initialize() {
  if(initialized) {
    return
  }

  unitTest()
  keyUtils.addEntropy(...keyUtils.cpuEntropy())
  assert(keyUtils.entropyCount() >= 128, 'insufficient entropy')

  initialized = true
}

PrivateKey.initialize = promiseAsync(initialize)

/**
  Unit test basic private and public key functionality.

  @throws {AssertError}
*/
function unitTest() {
  const privateKey = PrivateKey(hash.sha256(''))
  const wif = privateKey.toWif()

  assert.equal(wif, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss',
    'wif comparison test failed on a known private key')

  const pubkey = privateKey.toPublic().toString()
  assert.equal(pubkey, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM',
    'pubkey string comparison test failed on a known public key')

  doesNotThrow(() => PrivateKey.fromWif(wif), 'converting known wif from string')
  doesNotThrow(() => PublicKey.fromString(pubkey), 'converting known public key from string')

  unitTested = true
}

/** @private */
const doesNotThrow = (cb, msg) => {
  try {
    cb()
  } catch(error) {
    error.message = `${msg} ==> ${error.message}`
    throw error
  }
}

