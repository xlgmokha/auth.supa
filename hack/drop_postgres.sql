-- Undoes hack/init_postgres.sql: removes the auth schema and its roles.
-- Safe to re-run. Every object the migrations create lives in this schema, so
-- dropping it returns the database to its pre-migration state.
DROP SCHEMA IF EXISTS auth CASCADE;

-- The roles still own grants outside the schema (migrations grant SELECT to
-- the postgres role), and DROP ROLE fails while those exist. DROP OWNED BY
-- clears them, but errors if the role is already gone, hence the guards.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'supabase_auth_admin') THEN
        DROP OWNED BY supabase_auth_admin CASCADE;
        DROP ROLE supabase_auth_admin;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'supabase_admin') THEN
        DROP OWNED BY supabase_admin CASCADE;
        DROP ROLE supabase_admin;
    END IF;
END
$$;
