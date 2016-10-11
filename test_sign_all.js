var bitcoin = require('./src/index.js')
var bscript = bitcoin.script
var crypto = bitcoin.crypto
var Transaction = bitcoin.Transaction
var TransactionBuilder = bitcoin.TransactionBuilder
var TxSigner = bitcoin.TxSigner

var entropy = new Buffer('14bdfeac14bdfeac14bdfeac14bdfeac14bdfeac14bdfeac14bdfeac14bdfeac')
var root = bitcoin.HDNode.fromSeedBuffer(entropy)

function createCreditTransaction (scriptPubKey) {
  var creditOutput = {
    script: scriptPubKey,
    value: 50000
  }
  var creditTx = new Transaction()
  creditTx.ins.push({
    hash: new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
    vout: 0xffffffff,
    sequence: 0xffffffff,
    script: new Buffer('')
  })
  creditTx.outs.push(creditOutput)
  return creditTx
}

function testSpendTransaction (spk, rs, ws) {
  var creditTx = createCreditTransaction(spk)
  var creditTxid = creditTx.getHash()
  var creditUtxoIdx = 0

  var buildSpend = new TransactionBuilder()
  buildSpend.addInput(creditTxid, creditUtxoIdx, 0xffffffff)
  buildSpend.addOutput(creditTx.outs[0].script, creditTx.outs[0].value - 500)

  var signer = new TxSigner(buildSpend.buildIncomplete())
  signer.sign(0, root.keyPair, creditTx.outs[0], rs, ws)
  return signer.done()
}

// Standard Script Types, multisig/p2pkh/p2pk

var spkPubKeyHash = bscript.pubKeyHashOutput(crypto.ripemd160(crypto.sha256(root.getPublicKeyBuffer())))
var spkPubKey = bscript.pubKeyOutput(root.getPublicKeyBuffer())
var spkMultisig = bscript.multisigOutput(1, [root.getPublicKeyBuffer()]);

console.log('SPK Pub Key Hash')
var spendPubKeyHash = testSpendTransaction(spkPubKeyHash)
console.log(spendPubKeyHash)

console.log('SPK Pub Key')
var spendPubKey = testSpendTransaction(spkPubKey)
console.log(spendPubKey)

console.log('SPK Multisig')
var spendMultisig = testSpendTransaction(spkMultisig)
console.log(spendMultisig)

// P2sh versions

var p2shPubKeyHash = bscript.scriptHashOutput(crypto.ripemd160(crypto.sha256(spkPubKeyHash)));
var p2shPubKey = bscript.scriptHashOutput(crypto.ripemd160(crypto.sha256(spkPubKey)));
var p2shMultisig = bscript.scriptHashOutput(crypto.ripemd160(crypto.sha256(spkMultisig)));

console.log('SCRIPTHASH Multisig')
var spendP2shMultisig = testSpendTransaction(p2shMultisig, spkMultisig);
console.log(spendP2shMultisig)

console.log('SCRIPTHASH PubKeyHash')
var spendP2shPubKeyHash = testSpendTransaction(p2shPubKeyHash, spkPubKeyHash);
console.log(spendP2shPubKeyHash)

console.log('SCRIPTHASH PubKey')
var spendP2shPubKey = testSpendTransaction(p2shPubKey, spkPubKey);
console.log(spendP2shPubKey)

// Segwit versions

var witPubKeyHash = bscript.segWitScriptHashOutput(crypto.sha256(spkPubKeyHash));
var witPubKey = bscript.segWitScriptHashOutput(crypto.sha256(spkPubKey));
var witMultisig = bscript.segWitScriptHashOutput(crypto.sha256(spkMultisig));

console.log('Witness Multisig')
var spendWitMultisig = testSpendTransaction(witMultisig, null, spkMultisig);
console.log(spendWitMultisig)

console.log('Witness PubKeyHash')
var spendWitPubKeyHash = testSpendTransaction(witPubKeyHash, null, spkPubKeyHash);
console.log(spendWitPubKeyHash)

console.log('Witness PubKey')
var spendWitPubKey = testSpendTransaction(witPubKey, null, spkPubKey)
console.log(spendWitPubKey)


// P2sh Segwit versions

var p2shwitPubKeyHash = bscript.scriptHashOutput(crypto.ripemd160(crypto.sha256(witPubKeyHash)))
var p2shwitPubKey = bscript.scriptHashOutput(crypto.ripemd160(crypto.sha256(witPubKey)))
var p2shwitMultisig = bscript.scriptHashOutput(crypto.ripemd160(crypto.sha256(witMultisig)))

console.log('P2sh Witness Multisig')
var spendP2shWitMultisig = testSpendTransaction(p2shwitMultisig, witMultisig, spkMultisig);
console.log(spendP2shWitMultisig)

console.log('P2sh Witness PubKeyHash')
var spendP2shWitPubKeyHash = testSpendTransaction(p2shwitPubKeyHash, witPubKeyHash, spkPubKeyHash);
console.log(spendP2shWitPubKeyHash)

console.log('P2sh Witness PubKey')
var spendP2shWitPubKey = testSpendTransaction(p2shwitPubKey, witPubKey, spkPubKey);
console.log(spendP2shWitPubKey)

