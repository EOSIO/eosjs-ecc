/* eslint-env mocha */
const assert = require('assert')
const ecc = require('.')

describe('signature', () => {

  it('canonical', function() {
    const digest = '9d8815193d76ee236ef08e8b9fb675e6def3af8d8209d7665540ab9e17944e19'
    const wif = '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3'
    const actualSig = ecc.signHash(digest, wif)
    const expectedSig = 'SIG_K1_K3dztmFctY8QPgD6BEnxaV4s1gxyfHPZYTqHx8gH9Hiq2MLvn8Uc4ki6w7C89GVXAQ5JFM37BERe5qJSVHAqSkD8AabtKR'
    assert.equal(actualSig, expectedSig, 'known signature match')
  })

  it('canonical2', function() {
    const digest = Buffer.alloc(32, 0)
    const wif = '5HxQKWDznancXZXm7Gr2guadK7BhK9Zs8ejDhfA9oEBM89ZaAru'
    const actualSig = ecc.signHash(digest, wif)
    const expectedSig = 'SIG_K1_Jz9d1rKmMV51EY6dnU3pNaDiLvGTeVdxDZGvJEfAkdcwzs97gNg5yYPhPSdEg33Jyp5736Tnnzccf1p6h6vedXpHSUBio1'
    assert.equal(actualSig, expectedSig, 'known signature match')
  })

})
