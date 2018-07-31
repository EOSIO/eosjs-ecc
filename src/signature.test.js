/* eslint-env mocha */
const assert = require('assert')
const ecc = require('.')

describe('signature', () => {

  it('canonical', function() {
    const digest = '6cb75bc5a46a7fdb64b92efefca01ed7b060ab5e0d625226e8efbc0980c3ddc1'
    const wif = '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3'
    const actualSig = ecc.signHash(digest, wif)
    const expectedSig = 'SIG_K1_Kk1yUXAG2Cfo2qvWuJiyvaGdwZBQ1HzSf4EZ9arUTWBL4kTngLM1GSUU59bJUVAqwJ886CNQMcR7mmx323gjQGvhEU8WpX'
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
