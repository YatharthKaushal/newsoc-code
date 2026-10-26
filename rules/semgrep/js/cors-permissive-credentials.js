const cors = require('cors');
// ruleid: newsoc.js.cors-permissive-credentials
app.use(cors({ origin: true, credentials: true }));
// ruleid: newsoc.js.cors-permissive-credentials
app.use(cors({ credentials: true, origin: '*' }));
// ruleid: newsoc.js.cors-permissive-credentials
app.use(cors({ origin: '*', maxAge: 600, credentials: true }));
// ok: newsoc.js.cors-permissive-credentials
app.use(cors({ origin: 'https://app.example.com', credentials: true }));
// ok: newsoc.js.cors-permissive-credentials
app.use(cors({ origin: true }));
// ok: newsoc.js.cors-permissive-credentials
app.use(cors());
