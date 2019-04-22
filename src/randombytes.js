function getRandomValues(byteArray) {
    for (let i = 0; i < byteArray.length; i++) {
      byteArray[i] = Math.floor(256 * Math.random());
    }
};
function randomBytes(size, cb) {
    // phantomjs needs to throw
    if (size > 65536) {throw new Error('requested too many random bytes');}
    // in case browserify  isn't using the Uint8Array version
    var rawBytes = new global.Uint8Array(size);
  
    // This will not work in older browsers.
    // See https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
    if (size > 0) {
      // getRandomValues fails on IE if size == 0
      getRandomValues(rawBytes);
    }
    // XXX: phantomjs doesn't like a buffer being passed here
    var bytes = Buffer.from(rawBytes.buffer);
  
    if (cb) {
      cb(bytes);
    }
    return bytes;
};
module.exports = randomBytes;
  