CREATE TABLE public.clean_table (
    id      uuid PRIMARY KEY,
    user_id uuid NOT NULL
);

ALTER TABLE public.clean_table ENABLE ROW LEVEL SECURITY;

CREATE POLICY clean_owner_select
    ON public.clean_table FOR SELECT
    USING (auth.uid() = user_id);
