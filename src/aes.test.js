/* eslint-env mocha */
const assert = require('assert')
const ecc = require('.')

const alice = {
  public_key: 'EOS81xEWcDyZCxACZcYQekiWXLjuSoPMwmRv16nZMuqm2BtQMvXbg',
  private_key: '5JxhzyqYERz5MRSswNnDUXL1gFyM2m5Zxde9gGWfMkndbnjB8kD',
}
const bob = {
  public_key: 'EOS7jAEWX9d4nZJWNckkaxBsHyqbe6yrVH6VUoCzP6DLxHAEvsBKM',
  private_key: '5HrR1D5UbeeMETVR6Ud3Xc6PchVKbtAHmHiPmkmMQDqXY53bQKZ',
}

describe('encrypt/decrypt', () => {
  it('Decrypt should recover the original message', async function() {
    const message = Buffer.from("My first message")
    let box = ecc.Aes.encrypt(alice.private_key, bob.public_key, message)
    const decrypted = ecc.Aes.decrypt(bob.private_key, alice.public_key, box)
    assert.deepEqual(decrypted, message)
  })
  
  /* The following test fails with the normal eosjs-ecc */
  it('Tampered message should throw', async function() {
    const message = Buffer.from("My first message")
    let box = ecc.Aes.encrypt(alice.private_key, bob.public_key, message)
    
    // a little tampering
    box = Buffer.concat([box, box])
    
    assert.throws(function() {
      ecc.Aes.decrypt(bob.private_key, alice.public_key, box)
    })
  })
  
  it("encryption with pre-existing shared secret", async function() {
    const shared_secret = Buffer.from("1234")
    const message = Buffer.from("My first message")
    const box = ecc.Aes.encrypt_shared_secret(shared_secret, message)
    const decrypted =ecc.Aes.decrypt_shared_secret(shared_secret, box)
    assert.deepEqual(decrypted, message)
  })
  
})
  
