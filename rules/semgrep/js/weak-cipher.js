const crypto = require('crypto');
// ruleid: newsoc.js.weak-cipher
const c1 = crypto.createCipher('aes192', pw);
// ruleid: newsoc.js.weak-cipher
const c2 = crypto.createDecipher('aes192', pw);
// ruleid: newsoc.js.weak-cipher
const c3 = crypto.createCipheriv('aes-128-ecb', key, null);
// ruleid: newsoc.js.weak-cipher
const c4 = crypto.createCipheriv('des-ede3', key, iv);
// ok: newsoc.js.weak-cipher
const g1 = crypto.createCipheriv('aes-256-gcm', key, iv);
// ok: newsoc.js.weak-cipher
const g2 = crypto.createCipheriv('chacha20-poly1305', key, iv);
// ok: newsoc.js.weak-cipher
const h = crypto.createHash('sha256');
