# Moto Nzuri Agent Ops — Package Status

This ZIP preserves the supplied v3.9.0 Customer Care portal source and includes the supplied SIM Management module under `modules/sim-management/` when available.

**Important:** This is a source-package merge, not a claim that SIM Management is fully wired into the existing Express authentication/navigation/Supabase deployment. The requested expanded representative onboarding fields (branded/stocked status, stock check, National ID, payment channel, and signature) also require coordinated frontend, API, database, and admin-view changes; they are not claimed as completed by this packaging step.

Before deployment, review the SIM module README and migration, verify role checks on every route, apply migrations in a test Supabase project, and test representative + Customer Care admin visibility, map CRUD, duplicate prevention, and exports. National ID is sensitive personal data and should be access-restricted and handled under a defined retention policy.

No GitHub push, Supabase migration, or production deployment was performed.
