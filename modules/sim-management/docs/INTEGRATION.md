# Integration and deployment

## What is included
- Original supplied `Moto_Nzuri_Shop_Map2.html`, with a navigation link to SIM Management.
- SIM Management frontend (registration, search, monthly recharge, history, CSV/PDF links).
- Express router using existing Supabase client and existing Agent Ops auth middleware.
- PostgreSQL migration with unique constraints and role-based RLS.
- Setup steps below.

## Before merge
The uploaded artifact available for this build was the shop-map HTML, not the full Agent Ops source repository. Therefore this package integrates with the supplied map and provides a backend adapter, but it cannot safely patch unknown Agent Ops `server.js`, auth middleware, existing sidebar or schema automatically. A maintainer must wire the adapter to the actual project auth contract.

### Install
```bash
npm install json2csv pdfkit
```
(Express and `@supabase/supabase-js` are assumed to already exist in Agent Ops.)

### Apply migration
Run `supabase/migrations/202611040001_sim_management.sql` against the existing Agent Ops Supabase project. Review role claim semantics first. Current policy expects role in `app_metadata.role` or `user_metadata.role`; `app_metadata` is preferred because users cannot self-edit it. If Agent Ops uses a profile table or custom claims, modify `current_sim_role()` to use that trusted source.

### Mount API
In existing server entry point:
```js
import { createSimManagementRouter } from './modules/sim-management/src/routes/sim-management.js';

app.use('/api/sim-management', createSimManagementRouter({
  supabase,             // existing server-side Supabase client
  requireAuth,          // existing Agent Ops middleware; sets req.user
  getRole: req => req.user?.app_metadata?.role
    || req.user?.user_metadata?.role
    || req.user?.role
    || 'viewer',
  getActor: req => ({id:req.user?.id || null,email:req.user?.email || null})
}));

app.use('/sim-management', requireAuth,
  express.static('modules/sim-management/public'));
```
Adapt `getRole` / `getActor` to the real middleware; do not invent a second login. Do not use service role key in browser. The router's API auth must be checked in a live test.

### Map hosting
Serve `Moto_Nzuri_Shop_Map2.html` at `/Moto_Nzuri_Shop_Map2.html` or update the map link if Agent Ops uses another route. The map's new SIM link targets `/sim-management/`.

### Roles
- `admin`: read, register, recharge, export, audit visibility.
- `it_support`: read, register, recharge, export.
- `customer_service`: read, register, recharge, export.
- `viewer`: read and export only.
The role must come from trusted server-side identity claims.

### LAN + internet
The existing Node server should bind to `0.0.0.0` for trusted LAN access. Use the host machine's private LAN IP and firewall allowlist for the office subnet. For internet access deploy the existing app via its HTTPS host (Render or current provider) and use HTTPS. Do not expose the office PC or its database directly to the public internet.

### GitHub
Copy these files into the existing `Moto-Nzuri-Dev/Agent-Ops` working tree, review the diff, then:
```bash
git checkout -b feature/sim-management
git add Moto_Nzuri_Shop_Map2.html modules/sim-management supabase/migrations/202611040001_sim_management.sql docs/INTEGRATION.md
git commit -m "feat: integrate SIM management into Agent Ops"
git push -u origin feature/sim-management
```
Open a PR and test before merging to main. This build does not push to GitHub.

### Data safety / validation
- PIN/PUK intentionally not collected.
- Unique DB constraints prevent duplicate phone, IMSI, ICCID, and one recharge per SIM per month, including concurrent writes.
- CSV/PDF exports contain subscriber identifiers; restrict export permission, use HTTPS and do not email exports casually.
- Test with role-specific accounts, duplicate records, monthly recharge duplicate, export and mobile layout.
