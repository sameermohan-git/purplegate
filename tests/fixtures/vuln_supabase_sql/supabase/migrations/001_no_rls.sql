-- Fixture: CREATE TABLE in the public schema with NO RLS enabled.
-- The iac probe must flag this as Critical.

CREATE TABLE public.transactions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL,
    amount     numeric(14,2) NOT NULL,
    created_at timestamptz DEFAULT now()
);

-- Note: no ALTER TABLE ... ENABLE ROW LEVEL SECURITY; no CREATE POLICY.
