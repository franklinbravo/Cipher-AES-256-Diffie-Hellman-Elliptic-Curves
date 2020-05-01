const crypto = require('crypto')


const cipherTextPlain = (data, options) => {
  const { privKey = null, msg = "", pubKey } = data
  let ecdh = crypto.createECDH(options.curveName);
  ecdh.generateKeys();
  let plainText = Buffer.from(msg)
  let result = encrypt(privKey, Buffer.from(pubKey), plainText, options)
  return result;
}

const decipherTextPlain = (privKey, msgCipher, options) => {
  let ecdh = crypto.createECDH(options.curveName);
  ecdh.generateKeys();
  ecdh.setPrivateKey(privKey, 'hex')
  let result = decrypt(ecdh, msgCipher, options);
  return result;
}

//Preparacion para cifrado
const encrypt = (privateKey, publicKey, message, options) => {
  options = makeUpOptions(options);

  //Usar llave previamente guardada

  var ecdh = crypto.createECDH(options.curveName);
  ecdh.generateKeys();
  if (privateKey = null) {
    ecdh.setPrivateKey(privateKey, 'hex')
  }
  // R
  let R = Buffer.from(ecdh.getPublicKey(null, options.keyFormat));

  // S
  var sharedSecret = ecdh.computeSecret(publicKey);
  // uses KDF to derive a symmetric encryption and a MAC keys:
  // Ke || Km = KDF(S || S1)
  var hash = hashMessage(
    options.hashName,
    Buffer.concat(
      [sharedSecret, options.s1],
      sharedSecret.length + options.s1.length
    )
  );
  // Ke
  var encryptionKey = hash.slice(0, 64);
  // Km
  var macKey = hash.slice(hash.length / 2);
  // encriptar el mensaje:
  // c = E(Ke; m);
  var cipherText = symmetricEncrypt(options.symmetricCypherName, options.iv, encryptionKey, message);

  // computes the tag of encrypted message and S2:
  // d = MAC(Km; c || S2)
  var tag = macMessage(
    options.macName,
    macKey,
    Buffer.concat(
      [cipherText, options.s2],
      cipherText.length + options.s2.length
    )
  );
  // outputs R || c || d
  return Buffer.concat([R, cipherText, tag]);
};

const decrypt = (ecdh, message, options) => {
  options = makeUpOptions(options);
  var publicKeyLength = ecdh.getPublicKey(null, options.keyFormat).length;
  // R
  var R = message.slice(0, publicKeyLength);
  // c
  var cipherText = message.slice(publicKeyLength, message.length - options.macLength);
  // d
  var messageTag = message.slice(message.length - options.macLength);

  // S
  var sharedSecret = ecdh.computeSecret(R);
  // derives keys the same way as Alice did:
  // Ke || Km = KDF(S || S1)
  var hash = hashMessage(
    options.hashName,
    Buffer.concat(
      [sharedSecret, options.s1],
      sharedSecret.length + options.s1.length
    )
  );
  // Ke
  var encryptionKey = hash.slice(0, 64);
  // Km
  var macKey = hash.slice(hash.length / 2);

  // uses MAC to check the tag
  var keyTag = macMessage(
    options.macName,
    macKey,
    Buffer.concat(
      [cipherText, options.s2],
      cipherText.length + options.s2.length
    )
  );


  // uses symmetric encryption scheme to decrypt the message
  // m = E-1(Ke; c)
  return symmetricDecrypt(options.symmetricCypherName, options.iv, encryptionKey, cipherText);
}



const symmetricEncrypt = (cypherName, iv, key, plaintext) => {
  let cipher = crypto.createCipheriv(cypherName, key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}
const symmetricDecrypt = (cypherName, iv, key, ciphertext) => {
  let cipher = crypto.createDecipheriv(cypherName, key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}
const hashMessage = (cypherName, message) => {
  return crypto.createHash(cypherName).update(message).digest();
}
const macMessage = (cypherName, key, message) => {
  return crypto.createHmac(cypherName, key).update(message).digest();
}

const makeUpOptions = (options) => {
  options = options || {};
  if (options.hashName == undefined) {
    options.hashName = 'sha256';
  }
  if (options.hashLength == undefined) {
    options.hashLength = hashMessage(options.hashName, '').length;
  }
  if (options.macName == undefined) {
    options.macName = 'sha256';
  }
  if (options.macLength == undefined) {
    options.macLength = macMessage(options.hashName, '', '').length;
  }
  if (options.curveName == undefined) {
    options.curveName = 'secp256k1';
  }
  if (options.symmetricCypherName == undefined) {
    options.symmetricCypherName = 'aes-256-ecb';
    // use options.iv to determine is the cypher in ecb mode
    options.iv = null;
  }
  if (options.keyFormat == undefined) {
    options.keyFormat = 'uncompressed';
  }

  // S1 (optional shared information1)
  if (options.s1 == undefined) {
    options.s1 = Buffer.from([]);
  }
  // S2 (optional shared information2)
  if (options.s2 == undefined) {
    options.s2 = Buffer.from([]);
  }
  return options;
}
const iv = Buffer.alloc(16, 0);
var options = {
  hashName: 'sha256',
  hashLength: 32,
  macName: 'sha256',
  macLength: 32,
  curveName: 'secp521r1',
  symmetricCypherName: 'aes-256-cbc',
  iv: iv, // iv is used in symmetric cipher, set null if cipher is in ECB mode.
  keyFormat: 'compressed',
  s1: null, // optional shared information1
  s2: null // optional shared information2
}
//User A
let a = crypto.createECDH(options.curveName);
a.generateKeys();
//User B
let b = crypto.createECDH(options.curveName);
b.generateKeys();

let msg = "Ready"

const res1 = cipherTextPlain({ privKey: a.getPrivateKey(), pubKey: b.getPublicKey(), msg }, options)
const res2 = decipherTextPlain(b.getPrivateKey(), res1, options)
// result cipher
console.log(res1.toString('hex'));
// result decipher
console.log(res2.toString());
