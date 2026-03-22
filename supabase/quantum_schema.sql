-- ============================================================
-- Quantum Articles Schema
-- Run this in Supabase SQL Editor before first run
-- ============================================================

create table quantum_raw_articles (
    id              uuid primary key default gen_random_uuid(),
    source_feed     text not null,
    title           text not null,
    url             text not null unique,
    author          text,
    published_at    timestamptz,
    tags            text[],
    raw_content     text,
    collected_at    timestamptz not null default now()
);

create index on quantum_raw_articles (source_feed);
create index on quantum_raw_articles (published_at desc);
create index on quantum_raw_articles (collected_at desc);
