const CryptoJS = require('crypto-js');

/** @namespace hash */

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sha1(data, resultEncoding) {
    if (Buffer.isBuffer(data)) {
        data = CryptoJS.lib.WordArray.create(new Uint8Array(data));
    }
    
    let result = CryptoJS.algo.SHA1.create()
        .update(data)
        .finalize()
        .toString();
    
    if (!resultEncoding) {
        result = Buffer.from(result, 'hex');
    }
    
    return result;
}

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sha256(data, resultEncoding) {
    if (Buffer.isBuffer(data)) {
        data = CryptoJS.lib.WordArray.create(new Uint8Array(data));
    }
    
    let result = CryptoJS.algo.SHA256.create()
        .update(data)
        .finalize()
        .toString();
    
    if (!resultEncoding) {
        result = Buffer.from(result, 'hex');
    }
    
    return result;
}

/** @arg {string|Buffer} data
    @arg {string} [resultEncoding = null] - 'hex', 'binary' or 'base64'
    @return {string|Buffer} - Buffer when resultEncoding is null, or string
*/
function sha512(data, resultEncoding) {
    if (Buffer.isBuffer(data)) {
        data = CryptoJS.lib.WordArray.create(new Uint8Array(data));
    }
    
    let result = CryptoJS.algo.SHA512.create()
        .update(data)
        .finalize()
        .toString();
    
    if (!resultEncoding) {
        result = Buffer.from(result, 'hex');
    }
    
    return result;
}

function HmacSHA256(buffer, secret) {
    if (Buffer.isBuffer(buffer)) {
        buffer = CryptoJS.lib.WordArray.create(new Uint8Array(buffer));
    }
    if (Buffer.isBuffer(secret)) {
        secret = CryptoJS.lib.WordArray.create(new Uint8Array(secret));
    }
    
    let result = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, secret)
        .update(buffer)
        .finalize()
        .toString(CryptoJS.enc.Hex);
    
    result = Buffer.from(result, 'hex');
    
    return result;
}

function ripemd160(data) {
    if (Buffer.isBuffer(data)) {
        data = CryptoJS.lib.WordArray.create(new Uint8Array(data));
    }
    
    let result = CryptoJS.algo.RIPEMD160.create()
        .update(data)
        .finalize()
        .toString();
    
    result = Buffer.from(result, 'hex');
    
    return result;
}

// function hash160(buffer) {
//   return ripemd160(sha256(buffer))
// }
//
// function hash256(buffer) {
//   return sha256(sha256(buffer))
// }

//
// function HmacSHA512(buffer, secret) {
//   return crypto.createHmac('sha512', secret).update(buffer).digest()
// }

module.exports = {
    sha1: sha1,
    sha256: sha256,
    sha512: sha512,
    HmacSHA256: HmacSHA256,
    ripemd160: ripemd160
    // hash160: hash160,
    // hash256: hash256,
    // HmacSHA512: HmacSHA512
}
