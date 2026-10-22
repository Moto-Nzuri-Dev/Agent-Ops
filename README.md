# Moto Nzuri Field Ops v3.0.1.1

A professional field-operations system built with Node.js, Express, vanilla HTML/CSS/JS and Supabase. Current release: v3.4.0.

## Portals

- Agent registration: `/`
- Customer Care tickets: Admin dashboard → **Customer Care**
- Admin Operations Command: `/ops-7f3a9c-control`
- Driver Operations Portal: `/driver`

## Agent registration

Required:
- Shop name
- Location
- GPS coordinates
- Agent name
- Phone
- Visit date
- Selling status
- Machine status

Optional:
- KP / shop code
- WhatsApp number
- Alternative number
- Shop photo 1
- Shop photo 2

GPS attempts automatically at 15 seconds, 30 seconds and 60 seconds if a successful capture has not occurred. Manual capture remains available.

Duplicate protection uses KP + shop name only when KP is supplied.

## Admin Operations Command

The admin dashboard includes:

- Professional command-centre overview
- Shop and agent records
- Clickable WhatsApp contacts
- Google Maps coordinate links
- Location analytics
- Driver CRUD
- Driver activation/deactivation
- Driver password reset by admin
- Driver vehicle assignment
- Vehicle CRUD
- Current vehicle odometer
- Machine fuel logs
- Vehicle issue reports
- Security/audit activity
- CSV export for shop data

Admin authentication uses Supabase Auth plus `admin_allowlist`.

## Driver Operations Portal

Drivers sign in at `/driver` using the email assigned to their Supabase Auth account.

The driver email is server-derived and cannot be changed from the driver portal.

Driver dashboard includes:

- Assigned vehicle
- Current odometer
- Odometer updates
- Automatic GPS capture
- Machine fuel log form
- Shop name
- GPS pin
- Machine number
- KP number
- Fuel pumped
- Display photo (optional)
- Email address (read-only)
- Machine calibrated Yes/No
- First refill / Second refill / Custom selector
- Comments
- Vehicle problem reporting
- Vehicle issue resolution status
- Personal activity history

GPS attempts automatically at 15 seconds, 30 seconds and 60 seconds if a successful capture has not occurred. Manual capture is available.

## Driver account lifecycle

Only administrators create and manage driver accounts. The admin can:

1. Create a driver with an email, temporary password, name and phone.
2. Assign a vehicle.
3. Disable or reactivate the account.
4. Reset the password.
5. Change the assigned vehicle.
6. Delete the driver account.

The driver's login email is intentionally kept unchanged by driver-side forms.

## Supabase setup

1. Create/open the Supabase project.
2. Put the project URL and API keys in `.env`.
3. Run the **entire** `supabase/schema.sql` in Supabase SQL Editor.
4. Create your administrator under Supabase Authentication → Users.
5. Add that user's UUID and email to `public.admin_allowlist`.
6. Start the app with `npm run dev`.

Example admin allowlist insert:

```sql
insert into public.admin_allowlist (user_id, email)
values ('SUPABASE_AUTH_USER_UUID', 'admin@example.com')
on conflict (user_id) do update set email = excluded.email;
```

## Environment

Copy `.env.example` to `.env` and fill in:

```text
PORT=3000
SUPABASE_URL=https://yycpxzejmbqapvuizema.supabase.co
SUPABASE_PUBLISHABLE_KEY=YOUR_SUPABASE_PUBLISHABLE_KEY
SUPABASE_SECRET_KEY=YOUR_SUPABASE_SECRET_KEY
ADMIN_PATH=/ops-7f3a9c-control
DRIVER_PATH=/driver
MAX_PHOTO_MB=5
RATE_LIMIT_PER_MINUTE=60
LOG_LEVEL=info
```

The secret key stays server-side and is never embedded in browser JavaScript.

## Storage

The `shop-photos` bucket is private. Photo upload is server-side. Admin photo access uses short-lived signed URLs.

## Security

- Helmet security headers and CSP
- Compression
- Server-side Supabase secret key
- Supabase Auth
- Admin allowlist
- Active-driver authorization
- API rate limiting
- Structured request logging
- Security event logging
- Private photo storage
- Input validation
- No inline scripts
- No external CDN dependency

## Start

```bash
npm install
npm run dev
```

Production:

```bash
npm start
```


## v3.0.1 rendering fix
- Hardened admin UI event binding so optional/missing controls cannot crash the dashboard during startup.
- Kept admin script deferred and added null-safe event registration for controls.
- If admin login returns HTTP 401, verify the Supabase Auth email/password; HTTP 403 means the authenticated user is not in `admin_allowlist`.


## v3.2 admin UI and driver/fleet schema
The admin dashboard now has light/dark themes, accent themes, fullscreen mode, sticky table headers, scrollable data panels, responsive mobile navigation, and modal workflows. If Supabase reports missing `driver_profiles`, `vehicles`, `machine_fuel_logs`, or `vehicle_problems`, run `supabase/driver_fleet_migration.sql` (or the complete `supabase/schema.sql`) in Supabase SQL Editor. The application does not automatically create production tables.


## v3.3 unified access: administrators, drivers and agent representatives

### What is new
- One management dashboard now separates **Administrators**, **Drivers**, **Agent Representatives**, existing shop inspections, driver fuel logs, and representative shop submissions.
- Admins can create, edit, disable, reset passwords for (where applicable), and delete driver and representative accounts. Administrators can create other admin accounts, reset passwords, disable or delete other admins. The system prevents an admin from disabling/deleting their own account and prevents removing the last administrator.
- Agent representatives sign in at `/representative` using the email and password assigned by an administrator.
- The representative form captures **shop name, agent name, shop GPS coordinates, and M-Pesa number**. Representative email and submission time are derived by the server from the authenticated account, not trusted from the form.
- Representatives see only their own submission history. Admins see and export all representative submissions in the unified dashboard.

### Required Supabase migration
1. Open Supabase Dashboard → SQL Editor.
2. Run `supabase/representative_access_migration.sql` against the same project used by this app.
3. Keep the existing `schema.sql` and `driver_fleet_migration.sql` setup for the current shops, driver and fleet features. Do not delete existing tables.
4. Ensure the server deployment has `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_SECRET_KEY` set. The secret key belongs only in server environment variables and must never be placed in browser code or committed to GitHub.
5. Deploy the updated project. The representative portal is `/representative`; the admin dashboard remains at the configured `ADMIN_PATH`; driver portal remains at `/driver`.

### Creating accounts
- Sign into the admin dashboard and open **Drivers**, **Agent Reps**, or **Administrators**.
- Create an account with the person's email and a strong password of at least 8 characters. Share credentials privately and reset the password if needed.
- Drivers use `/driver`, representatives use `/representative`, and admins use the configured admin URL.

### Security notes
- Account creation and role checks happen server-side with Supabase Auth; the server secret key is not sent to clients.
- Representative submission records are associated with the authenticated representative user ID and email.
- GPS coordinates are device-reported estimates. Verify unusual submissions when needed; GPS alone is not proof that a visit occurred.
- HTTPS is required for browser geolocation on deployed sites (localhost is also allowed by browsers).


## v3.4.0 brand, representative dashboard and customer care

- Added local SVG Moto Nzuri logo and favicon assets. All portals reference `/moto-nzuri-logo.svg` and `/favicon.svg`; there is no third-party CDN dependency. Replace these two SVG assets with approved official artwork if your brand team supplies a final logo.
- Agent representatives now have dashboard metrics for total submissions, submissions today, submissions this month, and most recent submission, plus searchable submission history.
- Added an admin-only Customer Care ticket module based on the supplied operational ticket columns: ticket number/date, issue source, reported by, shop, location, issue category/description, priority, status, resolution, resolution date, CSR, month and quarter. Admins can create, edit, delete, search/filter and export tickets. Ticket number is generated by the database; month/quarter are derived from the ticket date.

### Required Customer Care migration
1. Open Supabase Dashboard → SQL Editor.
2. Run the full file `supabase/customer_care_migration.sql`.
3. Deploy the new project build to Render. Keep the Supabase secret key only in the server environment.
4. Sign in to the existing admin URL and open **Customer Care**.

This migration adds one new table and does not drop or replace existing data. The existing agent, driver, representative and admin routes remain in place.


## v3.5.0 additions

### Agent representative portal
- Added shop location/area, Till number, machine selling checkbox, and canisters-delivered count.
- Till numbers are stored as text so leading zeroes are preserved.
- Server-side duplicate checks and a database unique index block duplicate Till registrations; rejected duplicate attempts are recorded in security activity.
- Added a shared searchable master shop directory, map links, and WhatsApp sharing for shop records.
- Representatives can view tickets assigned to their account.

### Management ticket assignment
- Customer-care tickets can be assigned to an agent representative, a technician, or both.
- Ticket status supports Not resolved, Assigned, In progress, Resolved, Verified, Closed, On hold, and Reopened.
- Management can share ticket details over WhatsApp.
- Ticket assignment and status/resolution changes are recorded in ticket activity and security logs.

### Technician portal
- New `/technician` portal for technician sign-in and viewing only assigned tickets.
- Technicians can set tickets to In progress or On hold, or mark them Resolved after adding resolution notes.
- Admins can create technician accounts from the Technicians section in the management portal.

### Upgrade steps
1. Back up your Supabase database and current deployment.
2. In Supabase SQL Editor, run `supabase/v3.5.0_field_ops_migration.sql` after the existing v3.4.0 migrations.
3. Deploy the updated application folder. Do not upload `.env`; set `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and `SUPABASE_PUBLISHABLE_KEY` in the hosting provider's environment settings.
4. Sign in to the management portal, create technician accounts under **Technicians**, then create/edit customer-care tickets and assign the relevant representative/technician.
5. Test one new representative submission, one duplicate Till attempt, WhatsApp sharing, and a technician ticket update before rolling out to all users.

**Important:** Apply the migration before deploying this code. Existing representative records will have blank Till numbers and `0` canisters until updated; the unique Till index applies to nonblank Till numbers only. Keep the Supabase secret key server-side only.
