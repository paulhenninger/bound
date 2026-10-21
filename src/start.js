// Start the issuer, the relying party and the resource server together.
import { createIssuer } from './issuer/server.js';
import { createRelyingParty } from './rp/server.js';
import { createResourceServer } from './rs/server.js';

const issuer = await createIssuer();
await issuer.listen();
const rs = createResourceServer();
await rs.listen();
const rp = await createRelyingParty();
await rp.listen();

console.log(`
  Bound demo running

  Notebook (relying party)   ${rp.origin}      <- start here
  Bound ID (issuer)          ${issuer.origin}
  Notes API (resource)       ${rs.origin}

  CLI client (Flow B):       npm run cli -- "my first note"
`);
