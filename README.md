# Moto Nzuri Field Ops v3.0.1.1

A professional field-operations system built with Node.js, Express, vanilla HTML/CSS/JS and Supabase.

## Portals

- Agent registration: `/`
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
