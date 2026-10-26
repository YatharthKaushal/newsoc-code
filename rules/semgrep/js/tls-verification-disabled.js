const https = require('https');
// ruleid: newsoc.js.tls-verification-disabled
const agent1 = new https.Agent({ rejectUnauthorized: false });
// ruleid: newsoc.js.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
// ruleid: newsoc.js.tls-verification-disabled
const opts = { url: 'https://x', strictSSL: false };
// ok: newsoc.js.tls-verification-disabled
const agent2 = new https.Agent({ rejectUnauthorized: true });
// ok: newsoc.js.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
// ok: newsoc.js.tls-verification-disabled
const opts2 = { url: 'https://x', strictSSL: true };
