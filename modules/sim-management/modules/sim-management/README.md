# SIM Management module

Mount this module inside the existing Moto Nzuri Agent Ops application. It uses the existing Supabase project and existing authentication middleware; it does not create a second login system.

## Integration contract
- Server-side Supabase client is passed into `createSimManagementRouter`.
- Existing authentication middleware must populate `req.user`.
- `getRole(req)` must return one of `admin`, `it_support`, `customer_service`, `viewer` from a trusted server-side claim/profile lookup.
- Do not trust role values from request bodies or query parameters.
- The supplied shop map now includes a navigation link to `/sim-management/`. Serve the module page at that route behind the same login.

## Install
```bash
npm install json2csv pdfkit
```
Supabase JS and Express are assumed to be installed already in Agent Ops.

## Mount
```js
import { createSimManagementRouter } from './modules/sim-management/src/routes/sim-management.js';

app.use('/api/sim-management', requireAuth,
  createSimManagementRouter({ supabase, getRole, getActor }));
app.use('/sim-management', requireAuth,
  express.static('modules/sim-management/public'));
```
The router itself also accepts `requireAuth` if preferred; to avoid duplicate middleware, use the example below instead:
```js
app.use('/api/sim-management', createSimManagementRouter({
  supabase, requireAuth, getRole, getActor
}));
```

## Important existing-app checks
Before merging, reconcile `getRole` and `getActor` with the actual Agent Ops auth/session structure. The existing Agent Ops source was not supplied with the shop map upload, so no assumptions about its exact middleware or navigation component are made here.
