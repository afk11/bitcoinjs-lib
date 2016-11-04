var bscript = require('./script')
var crypto = require('./crypto')
var bufferEquals = require('buffer-equals')
var typeforce = require('typeforce')
var types = require('./types')
var ECPair = require('./ecpair')
var ECSignature = require('./ecsignature')
var Transaction = require('./transaction')
var EMPTY_SCRIPT = new Buffer(0)
var SIGNABLE_SCRIPTS = [
  bscript.types.MULTISIG,
  bscript.types.P2PKH,
  bscript.types.P2PK
]
var SOLVABLE_SCRIPTS = [
  bscript.types.MULTISIG,
  bscript.types.P2PKH,
  bscript.types.P2PK,
  bscript.types.P2WSH,
  bscript.types.P2WPKH,
  bscript.types.P2SH
]
var ALLOWED_P2SH_SCRIPTS = [
  bscript.types.MULTISIG,
  bscript.types.P2PKH,
  bscript.types.P2PK,
  bscript.types.P2WSH,
  bscript.types.P2WPKH
]

/**
 * Design goals
 *
 *  - tolerate arbitrary sigHashType's on signatures
 *  - given tx, nIn, txOut, we can reliably check a redeemScript and eventual witnessScript at signing
 *  - reliably extract signatures from a signed input
 *  - create, and re-serialize given minimal state
 *  - clear separation of 'standard scripts' and the various script-hash scripts
 *
 * @param tx - the transaction we want to sign
 * @param nIn - the input we will sign here
 * @param txOut - the transaction output containing the value and spkPubKeyHash.
 */
function InSigner (tx, nIn, txOut) {
  if ((tx instanceof Transaction) === false) {
    throw new Error('A transaction is required for InSigner')
  }

  this.tx = tx
  this.nIn = nIn
  this.txOut = txOut
  this.canSign = false
  this.publicKeys = []
  this.signatures = []
  this.requiredSigs = null

  this.extractScriptSig()
}

function calculateSignature (tx, nIn, key, scriptCode, value, sigHashType, sigVersion) {
  var hash = sigVersion === 1
    ? tx.hashForWitnessV0(nIn, scriptCode, value, sigHashType)
    : tx.hashForSignature(nIn, scriptCode, sigHashType)

  return key.sign(hash).toScriptSignature(sigHashType)
}

/**
 * Helper function to produce a script signature
 *
 * @param key
 * @param scriptCode
 * @param sigHashType
 * @param sigVersion
 * @returns Buffer
 */
InSigner.prototype.calculateSignature = function (key, scriptCode, sigHashType, sigVersion) {
  var hash = sigVersion === 1
    ? this.tx.hashForWitnessV0(this.nIn, scriptCode, this.txOut.value, sigHashType)
    : this.tx.hashForSignature(this.nIn, scriptCode, sigHashType)

  return key.sign(hash).toScriptSignature(sigHashType)
}

/**
 * This algorithm attempts to link signatures based on
 * the ordering OP_CHECKMULTISIG would use.
 * This does NOT handle arbitrary linking of sigs<->keys.
 *
 * @param ecsigs - list of signature buffers
 * @param publicKeys - public keys to try and link against
 * @param scriptCode - scriptCode - for verification
 * @param sigVersion - transaction hashing version
 * @returns {Array}
 */
InSigner.prototype.sortMultisigs = function (ecsigs, publicKeys, scriptCode, sigVersion) {
  var results = []
  var hash
  var ikey = 0
  var isig = 0
  var sig, key
  var success = true
  var sigsCount = ecsigs.length
  var keysCount = publicKeys.length
  while (success && ecsigs.length > 0) {
    sig = ECSignature.parseScriptSignature(ecsigs[isig])
    key = publicKeys[ikey]
    hash = this.tx.hashForSignature(this.nIn, scriptCode, sig.hashType, sigVersion === 1, this.txOut.value)
    if (key.verify(hash, sig.signature)) {
      isig++
      results[key.getPublicKeyBuffer().toString('binary')] = ecsigs[isig]
    }
    ikey++
    if (sigsCount > keysCount) {
      success = false
    }
  }

  return results
}

/**
 * This function contains the code for parsing any SIGNABLE_SCRIPTS
 * TODO: remove scriptCode & sigVersion, only required for sorting multisigs
 *
 * @param scriptType - determined scriptType
 * @param data - data from a decompiled scriptSig or witness
 * @param scriptCode - the script code the data is meant to solve
 * @param sigVersion - signature hashing version
 */
InSigner.prototype.extractFromData = function (scriptType, data, scriptCode, sigVersion) {
  if (scriptType === bscript.types.P2PKH) {
    this.canSign = true
    this.requiredSigs = 1
    if (data.length === 2 && bscript.isCanonicalSignature(data[0])) {
      this.signatures = [data[0]]
      this.publicKeys = [ECPair.fromPublicKeyBuffer(data[1])]
    }
  }

  if (scriptType === bscript.types.P2PK) {
    this.canSign = true
    this.requiredSigs = 1
    if (data.length === 1 && bscript.isCanonicalSignature(data[0])) {
      this.signatures = [data[0]]
    }
  }

  if (scriptType === bscript.types.MULTISIG) {
    var multisigData = bscript.parseMultisigScript(bscript.decompile(scriptCode))
    this.canSign = true
    this.requiredSigs = multisigData.nRequiredSigs
    this.publicKeys = multisigData.publicKeys

    if (data.length > 1) {
      var sigs = this.sortMultisigs(data.slice(1, -1), this.publicKeys, scriptCode, sigVersion)
      for (var i = 0, l = this.publicKeys.length; i < l; i++) {
        var str = this.publicKeys[ i ].getPublicKeyBuffer().toString('binary')
        if (sigs[ str ] !== undefined && bscript.isCanonicalSignature(sigs[str])) {
          this.signatures[ i ] = sigs[ str ]
        }
      }
    }
  }
}

/**
 * A high level function for parsing a signature. (ie, handles P2SH / segwit)
 * Extract signatures / nRequiredSigs / public keys / redeemScript / witnessScript
 * from any representation of the BASE_TYPES
 */
InSigner.prototype.extractScriptSig = function () {
  var input = this.tx.ins[this.nIn]
  var scriptCode = this.txOut.script
  var scriptType = bscript.classifyOutput(scriptCode)
  var sigChunks = bscript.convertScriptToWitness(input.script)
  if (SIGNABLE_SCRIPTS.indexOf(scriptType)) {
    this.extractFromData(scriptType, sigChunks, scriptCode, Transaction.SIG_V0)
  }

  if (scriptType === bscript.types.P2SH && sigChunks.length > 0) {
    var scriptHash = bscript.decompile(scriptCode)[1]
    scriptCode = sigChunks[sigChunks.length - 1]
    scriptType = bscript.classifyOutput(scriptCode)
    if (ALLOWED_P2SH_SCRIPTS.indexOf(scriptType)) {
      if (!bufferEquals(scriptHash, crypto.hash160(scriptCode))) {
        throw new Error('Redeem script does not match script hash')
      }

      this.extractFromData(scriptType, sigChunks.slice(0, -1), scriptCode, Transaction.SIG_V0)
      this.redeemScript = scriptCode
    }
  }

  if (scriptType === bscript.types.P2WPKH) {
    if (input.witness.length === 2) {
      var witnessKeyHash = bscript.decompile(scriptCode)[1]
      if (!bufferEquals(witnessKeyHash, crypto.hash160(input.witness[1]))) {
        throw new Error('Public key does not match key-hash')
      }
      this.extractFromData(bscript.types.P2PKH, input.witness)
    }
  } else if (scriptType === bscript.types.P2WSH && input.witness.length > 0) {
    var witnessScriptHash = bscript.decompile(scriptCode)[1]
    scriptCode = input.witness[input.witness.length - 1]
    scriptType = bscript.classifyOutput(scriptCode)
    if (SIGNABLE_SCRIPTS.indexOf(scriptType)) {
      if (!bufferEquals(witnessScriptHash, crypto.sha256(scriptCode))) {
        throw new Error('Redeem script does not match script hash')
      }
      this.extractFromData(scriptType, input.witness.slice(0, -1), scriptCode, Transaction.SIG_V1)
      this.witnessScript = scriptCode
    }
  }
}

/**
 * Attempt to 'solve' the given `scriptCode`. Returns an object:
 * {
 *   type: ...,
 *   solvedBy: []
 * }
 *
 * while also saving signatures/pubkeys as state.
 * - For script-hash commitments, `solvedBy` is an array where the
 *   first element is the script-hash (P2SH / P2WSH)
 * - For other script types, `solvedBy` is the list of keys/hashes
 *   the private key should be checked against.
 *
 * @param key - the private key to solve with
 * @param scriptCode - the scriptCode to solve
 * @param sigHashType
 * @param sigVersion - signature hashing version, ie, normal or segwit
 * @returns {{type: *, solvedBy: Array}}
 */
InSigner.prototype.solve = function (key, scriptCode, sigHashType, sigVersion) {
  typeforce(types.Number, sigHashType)
  typeforce(types.Number, sigVersion)

  var outputType = bscript.classifyOutput(scriptCode)
  var decompiled = bscript.decompile(scriptCode)
  var solvedBy = []

  switch (outputType) {
    // We can only determine the relevant hash from these:
    case bscript.types.P2SH:
      solvedBy.push(decompiled[1])
      break
    case bscript.types.P2WSH:
      solvedBy.push(decompiled[1])
      break

    // We can solve signatures for these
    // When adding a new script type, edit here
    case bscript.types.P2PK:
      this.canSign = true
      solvedBy[0] = decompiled[0]
      if (bufferEquals(key.getPublicKeyBuffer(), decompiled[0])) {
        this.signatures[0] = calculateSignature(this.tx, this.nIn, key, scriptCode, this.txOut.value, sigHashType, sigVersion)
        this.publicKeys[0] = key
      } else {
        throw new Error('Signing input with wrong private key')
      }

      this.requiredSigs = 1
      break
    case bscript.types.P2PKH:
      this.canSign = true
      solvedBy[0] = decompiled[2]
      if (bufferEquals(crypto.hash160(key.getPublicKeyBuffer()), decompiled[2])) {
        this.signatures[0] = calculateSignature(this.tx, this.nIn, key, scriptCode, this.txOut.value, sigHashType, sigVersion)
        this.publicKeys[0] = key
      } else {
        throw new Error('Signing input with wrong private key')
      }

      this.requiredSigs = 1
      break
    case bscript.types.MULTISIG:
      this.canSign = true
      var multisigInfo = bscript.parseMultisigScript(bscript.decompile(scriptCode))
      this.requiredSigs = multisigInfo.nRequiredSigs
      this.publicKeys = multisigInfo.publicKeys

      var myPublicKey = key.getPublicKeyBuffer()
      var thePublicKey
      var signed = false

      for (var i = 0, keyLen = multisigInfo.publicKeyBuffers.length; i < keyLen; i++) {
        thePublicKey = multisigInfo.publicKeyBuffers[i]
        if (bufferEquals(myPublicKey, thePublicKey)) {
          signed = true
          this.signatures[i] = calculateSignature(this.tx, this.nIn, key, scriptCode, this.txOut.value, sigHashType, sigVersion)
        }
      }

      if (!signed) {
        throw new Error('Signing input with wrong private key')
      }
      break
    case bscript.types.P2WPKH:
      this.canSign = true
      solvedBy[0] = decompiled[1]
      this.requiredSigs = 1
      if (bufferEquals(key.getPublicKeyBuffer(), decompiled[1])) {
        this.signatures[0] = calculateSignature(this.tx, this.nIn, key, bscript.pubKeyHashOutput(decompiled[1]), this.txOut.value, sigHashType, Transaction.SIG_V1)
        this.publicKeys[0] = ECPair.fromPublicKeyBuffer(decompiled[1])
      } else {
        throw new Error('Signing input with the wrong private key')
      }

      break
  }

  return {
    type: outputType,
    solvedBy: solvedBy
  }
}

/**
 * High level sign function
 * @param key - the private key
 * @param redeemScript - the redeemScript (optional unless UTXO is P2SH)
 * @param witnessScript - the redeemScript (optional unless witness is used)
 * @param sigHashType
 * @returns {boolean}
 */
InSigner.prototype.sign = function (key, redeemScript, witnessScript, sigHashType) {
  var solved, solution

  // Attempt to solve the txOut script with the key / sigHashType
  // Not solved if the script is not on our list of signable scripts.
  solution = this.solve(key, this.txOut.script, sigHashType, Transaction.SIG_V0)
  solved = SOLVABLE_SCRIPTS.indexOf(solution.type) !== -1

  // If the spkPubKeyHash was solvable, and the type is P2SH, we try again with the redeemScript
  if (solved && solution.type === bscript.types.P2SH) {
    if (redeemScript === undefined) {
      throw new Error('redeem script required for P2SH')
    }
    if (!types.Buffer(redeemScript)) {
      throw new Error('redeem script must be a buffer')
    }
    if (!bufferEquals(crypto.hash160(redeemScript), solution.solvedBy[0])) {
      throw new Error("Incorrect redeem script: hash doesn't match")
    }
    // solution updated, type is the type of the redeemScript
    // Not solved if the solution is not signable, or is P2SH again.
    solution = this.solve(key, redeemScript, sigHashType, Transaction.SIG_V0)
    solved = ALLOWED_P2SH_SCRIPTS.indexOf(solution.type) !== -1
    if (solved) {
      this.redeemScript = redeemScript
    }
  }

  // If the spkPubKeyHash was (still - because of P2SH)
  if (solved) {
    if (solution.type === bscript.types.P2WPKH) {
      var keyHashScript = bscript.pubKeyHashOutput(solution.solvedBy[0])
      this.solve(key, keyHashScript, sigHashType, Transaction.SIG_V1)
    } else if (solution.type === bscript.types.P2WSH) {
      if (witnessScript === undefined) {
        throw new Error('Witness script required for P2WSH')
      }
      if (!types.Buffer(witnessScript)) {
        throw new Error('Witness script must be a buffer')
      }
      if (!bufferEquals(crypto.sha256(witnessScript), solution.solvedBy[0])) {
        throw new Error("Incorrect witness script: hash doesn't match")
      }

      var subSolution = this.solve(key, witnessScript, sigHashType, Transaction.SIG_V1)
      solved = SIGNABLE_SCRIPTS.indexOf(subSolution.type) !== -1
      if (solved) {
        this.witnessScript = witnessScript
      }
    }
  }

  return solved
}

/**
 * Return whether the input is fully signed (so
 * long as the fields are populated correctly)
 *
 * @returns {boolean}
 */
InSigner.prototype.isFullySigned = function () {
  return this.requiredSigs !== 0 && this.requiredSigs === this.signatures.length
}

/**
 * Take a `sigData` and populate the scriptSig given
 * the signatures/keys we know about.
 *
 * @param outputType - output script type
 * @param sigData - object containing `scriptSig` and `witness`
 * @returns {boolean}
 */
InSigner.prototype.serializeStandard = function (outputType, sigData) {
  // When adding a new script type, edit here
  switch (outputType) {
    case bscript.types.P2PK:
      if (this.isFullySigned()) {
        sigData.scriptSig = bscript.pubKeyInput(this.signatures[ 0 ])
      }
      return true
    case bscript.types.P2PKH:
      if (this.isFullySigned()) {
        sigData.scriptSig = bscript.pubKeyHashInput(this.signatures[ 0 ], this.publicKeys[ 0 ].getPublicKeyBuffer())
      }
      return true
    case bscript.types.MULTISIG:
      sigData.scriptSig = bscript.multisigInput(this.signatures.map(function (signature) {
        if (signature instanceof Buffer === false) {
          throw new Error('debugging probably required')
        }
        return signature
      }))
      return true
    default:
      return false
  }
}

/**
 * Serialize an inputs signature data, fully accounting
 * for P2SH / P2WSH
 *
 * @returns {{scriptSig: Buffer, witness: Array}}
 */
InSigner.prototype.serializeSigData = function () {
  var type = bscript.classifyOutput(this.txOut.script)
  var sigData = {
    scriptSig: EMPTY_SCRIPT,
    witness: []
  }

  var isSerialized = this.serializeStandard(type, sigData)
  var p2sh = false
  if (!isSerialized && type === bscript.types.P2SH) {
    p2sh = true
    type = bscript.classifyOutput(this.redeemScript)
    isSerialized = this.serializeStandard(type, sigData)
  }

  if (!isSerialized && type === bscript.types.P2WPKH) {
    sigData = {
      scriptSig: EMPTY_SCRIPT,
      witness: [this.signatures[0], this.publicKeys[0].getPublicKeyBuffer()]
    }
  } else if (!isSerialized && type === bscript.types.P2WSH) {
    type = bscript.classifyOutput(this.witnessScript)
    isSerialized = this.serializeStandard(type, sigData)

    if (isSerialized) {
      var wit = bscript.convertScriptToWitness(sigData.scriptSig)
      wit.push(this.witnessScript)
      sigData.scriptSig = EMPTY_SCRIPT
      sigData.witness = wit
    }
  }

  if (p2sh) {
    sigData.scriptSig = bscript.scriptHashInput(sigData.scriptSig, this.redeemScript)
  }

  return sigData
}

/**
 * Create a TxSigner for this transaction instance
 * @param tx
 * @constructor
 */
function TxSigner (tx) {
  if (tx === undefined || (tx instanceof Transaction) === false) {
    throw new Error('A transaction is required for TxSigner')
  }

  this.tx = tx.clone()
  this.states = []
}

/**
 * Sign a transaction.
 *
 * @param nIn - the input to sign
 * @param key - the private key to sign with
 * @param txOut - the transaction output referenced in the input (containing value & script)
 * @param redeemScript - the redeemScript is optional, unless called for by the spkPubKeyHash
 * @param witnessScript - the witnessScript is optional, unless called for by the spkPubKeyHash/P2SH script
 * @param sigHashType - SIGHASH type to sign with
 */
TxSigner.prototype.sign = function (nIn, key, txOut, sigHashType, redeemScript, witnessScript) {
  typeforce(types.Number, nIn)
  typeforce(types.Object, txOut)
  typeforce(types.maybe(Number), sigHashType)
  typeforce(types.maybe(Buffer), redeemScript)
  typeforce(types.maybe(Buffer), witnessScript)

  if (sigHashType === undefined) {
    sigHashType = Transaction.SIGHASH_ALL
  }

  if (this.states[nIn] === undefined) {
    this.states[nIn] = new InSigner(this.tx, nIn, txOut)
  }

  if (!this.states[nIn].sign(key, redeemScript, witnessScript, sigHashType)) {
    throw new Error('Unsignable input: ', nIn)
  }

  return true
}

/**
 * Produce a Transaction with our changes.
 */
TxSigner.prototype.done = function () {
  var tx = this.tx.clone()

  var states = this.states
  for (var i = 0, l = tx.ins.length; i < l; i++) {
    if (this.states[i] !== undefined) {
      var sigData = states[i].serializeSigData()
      tx.ins[i].script = sigData.scriptSig
      tx.ins[i].witness = sigData.witness
    }
  }
  return tx
}

module.exports = TxSigner
