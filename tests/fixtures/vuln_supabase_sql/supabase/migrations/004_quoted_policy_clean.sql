-- Fixture: clean table whose policy uses a DOUBLE-QUOTED policy name with
-- internal spaces. The iac probe regex previously matched the policy name
-- as `\S+` and broke on the first space inside the quotes — see
-- regression in financial-tracker scan 2026-04-25 where `file_uploads`
-- was falsely flagged "RLS enabled but no policy".
--
-- iac probe must NOT flag this table.

CREATE TABLE public.invoices (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL,
    amount     numeric(14,2)
);

ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own invoices"
    ON invoices FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own invoices"
    ON public.invoices FOR INSERT
    WITH CHECK (auth.uid() = user_id);
