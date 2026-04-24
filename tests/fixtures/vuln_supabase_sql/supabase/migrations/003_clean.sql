-- Fixture: clean table with RLS + policy. iac probe must NOT flag.

CREATE TABLE public.receipts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL,
    total      numeric(14,2)
);

ALTER TABLE public.receipts ENABLE ROW LEVEL SECURITY;

CREATE POLICY receipts_owner_select
    ON public.receipts FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY receipts_owner_insert
    ON public.receipts FOR INSERT
    WITH CHECK (auth.uid() = user_id);
