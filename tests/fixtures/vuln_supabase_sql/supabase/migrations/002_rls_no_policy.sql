-- Fixture: RLS enabled but no CREATE POLICY. iac probe flags High.

CREATE TABLE public.profiles (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL,
    full_name  text
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
-- Intentionally no CREATE POLICY.
