/* global describe, it */

var bscript = require('../src/script')
var bcrypto = require('../src/crypto')
var ECPair = require('../src/ecpair')
var NETWORKS = require('../src/networks')
var TransactionBuilder = require('../src/transaction_builder')
var Transaction = require('../src/transaction')
var BigInteger = require('bigi')

describe('TransactionBuilder', function () {

  var value = 1000000

  var network = NETWORKS['testnet']

  it('cashtestcase2', function () {
    value = 5000000000
    var txid = '3bd5c0881a0d180447eda4661448419e42b789721f38585955e6c089e3ba44b9'
    var vout = 0

    var wif = 'cShZXG9kQUsU2zW456rhk9CBQzrT3bCzVVrtiWcEaKnfoy79dejq'
    var keyPair = ECPair.fromWIF(wif, network)

    var pk = keyPair.getPublicKeyBuffer()
    var spk = bscript.pubKey.output.encode(pk)

    var txb = new TransactionBuilder(network)
    txb.addInput(txid, vout, Transaction.DEFAULT_SEQUENCE, spk)
    txb.addOutput('mwjxBrT3hvSPXHmRgf8hXmwYpARp5whcge', value)
    txb.enableBitcoinCash(true)
    txb.setVersion(2)

    var hashType = Transaction.SIGHASH_ALL | Transaction.SIGHASH_BITCOINCASHBIP143

    txb.sign(0, keyPair, null, hashType, value)

    var tx = txb.build()
    console.log(tx.toHex())
    console.log(tx)
  })

  it('cashtestcase3', function () {
    value = 1 * 1e8
    var txid = 'bfbbca3819ac8a9a23bfd4e49df84daaa736048995390759105975dfca6cad2f'
    var vout = 0

    var wif = 'cRoWXJYEneiQfrdixBFrK15e5PxNkUkaB9n4dHSjaDsvT7wtrKBY'
    var keyPair = ECPair.fromWIF(wif, network)

    var pk = keyPair.getPublicKeyBuffer()
    // var spk = bscript.pubKey.output.encode(pk)

    var txb = new TransactionBuilder(network)
    txb.addInput(txid, vout, Transaction.DEFAULT_SEQUENCE)
    txb.addOutput('mzDktdwPcWwqg8aZkPotx6aYi4mKvDD7ay', value - 10000)
    txb.enableBitcoinCash(true)
    txb.setVersion(2)

    var hashType = Transaction.SIGHASH_ALL | Transaction.SIGHASH_BITCOINCASHBIP143

    txb.sign(0, keyPair, null, hashType, value)

    var tx = txb.build()
    console.log(tx.toHex())
    console.log(tx)
  })
})
