-- ============================================================
-- Cyber Security Intelligence Hub - Supabase Schema
-- Run this in Supabase SQL Editor before first pipeline run
-- ============================================================

-- Required for RAG vector search
create extension if not exists vector;

-- -------------------------------------------------------

create table mitre_techniques (
    id              uuid primary key default gen_random_uuid(),
    technique_id    text not null unique,   -- e.g. T1566.001
    name            text not null,
    tactic          text not null,
    description     text not null,
    embedding       vector(768) not null,   -- text-embedding-004 dims
    updated_at      timestamptz not null default now()
);

create index on mitre_techniques using hnsw (embedding vector_cosine_ops);

-- Similarity search function used by article_parser.py
create or replace function match_mitre_techniques(
    query_embedding vector(768),
    match_count     int default 5
)
returns table (
    technique_id text,
    name         text,
    tactic       text,
    similarity   float
)
language sql stable as $$
    select
        technique_id,
        name,
        tactic,
        1 - (embedding <=> query_embedding) as similarity
    from mitre_techniques
    order by embedding <=> query_embedding
    limit match_count;
$$;

create table raw_articles (
    id              uuid primary key default gen_random_uuid(),
    source_feed     text not null,
    title           text not null,
    url             text not null unique,
    published_at    timestamptz,
    raw_content     text,
    status          text not null default 'pending',
    error_message   text,
    collected_at    timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

create index on raw_articles (status);
create index on raw_articles (collected_at desc);

-- -------------------------------------------------------

create table parsed_articles (
    id              uuid primary key default gen_random_uuid(),
    raw_article_id  uuid not null references raw_articles(id),
    title           text not null,
    url             text not null,
    published_at    timestamptz,
    summary         text,
    ai_analysis     jsonb not null,
    vuln_status     text not null default 'pending',
    method_status   text not null default 'pending',
    strategy_status text not null default 'pending',
    actor_status    text not null default 'pending',
    incident_status text not null default 'pending',
    parsed_at       timestamptz not null default now()
);

create index on parsed_articles (vuln_status);
create index on parsed_articles (method_status);
create index on parsed_articles (strategy_status);
create index on parsed_articles (actor_status);
create index on parsed_articles (incident_status);
create index on parsed_articles (raw_article_id);

-- -------------------------------------------------------

create table vulnerabilities (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    cve_id              text,
    vuln_description    text not null,
    affected_products   text[],
    severity            text,
    cvss_score          numeric(3,1),
    patch_available     boolean,
    patch_url           text,
    extracted_at        timestamptz not null default now()
);

create index on vulnerabilities (cve_id);
create index on vulnerabilities (parsed_article_id);
create index on vulnerabilities (severity);

-- -------------------------------------------------------

create table methodologies (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    technique_name      text not null,
    mitre_technique_id  text,
    mitre_tactic        text,
    description         text not null,
    threat_actor        text,
    extracted_at        timestamptz not null default now()
);

create index on methodologies (mitre_technique_id);
create index on methodologies (mitre_tactic);
create index on methodologies (parsed_article_id);

-- -------------------------------------------------------

create table strategies (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    recommendation      text not null,
    category            text,
    priority            text,
    applies_to          text[],
    related_cve_ids     text[],
    extracted_at        timestamptz not null default now()
);

create index on strategies (category);
create index on strategies (parsed_article_id);

-- -------------------------------------------------------

create table threat_actors (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    name                text not null,
    aliases             text[],
    origin_country      text,
    targeted_sectors    text[],
    motivation          text,
    extracted_at        timestamptz not null default now()
);

create index on threat_actors (name);
create index on threat_actors (origin_country);
create index on threat_actors (parsed_article_id);

-- -------------------------------------------------------

create table incidents (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    organization        text,
    sector              text,
    attack_type         text,
    data_compromised    text[],
    incident_date       date,
    extracted_at        timestamptz not null default now()
);

create index on incidents (attack_type);
create index on incidents (sector);
create index on incidents (incident_date desc);
create index on incidents (parsed_article_id);

-- -------------------------------------------------------

create table ai_validations (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    source_table        text not null,      -- 'methodologies' or 'vulnerabilities'
    source_row_id       uuid not null,      -- id in the source table
    field_type          text not null,      -- 'mitre_id' or 'cve_id'
    predicted_value     text not null,      -- what LLM predicted
    is_valid            boolean not null,   -- does it exist in the real DB
    validated_at        timestamptz not null default now()
);

create index on ai_validations (parsed_article_id);
create index on ai_validations (field_type, is_valid);
create index on ai_validations (source_row_id);

-- -------------------------------------------------------

create table review_queue (
    id                  uuid primary key default gen_random_uuid(),
    parsed_article_id   uuid not null references parsed_articles(id),
    review_type         text not null,      -- 'mitre_no_match'
    behavior_text       text not null,      -- elgesio aprašymas kurio nepavyko susieti
    gemma_suggestion    text,               -- ką Gemma manė kad tai yra (haliucinacija)
    rag_candidates      text[],             -- kokie 5 kandidatai buvo pateikti
    status              text not null default 'pending',  -- pending, reviewed, dismissed
    reviewed_at         timestamptz,
    reviewer_note       text,
    created_at          timestamptz not null default now()
);

create index on review_queue (status);
create index on review_queue (parsed_article_id);

-- ============================================================
-- MIGRATION: run this if upgrading an existing database
-- (skip if creating fresh schema)
-- ============================================================
-- alter table parsed_articles rename column claude_analysis to ai_analysis;
-- create index on parsed_articles (actor_status);
-- create index on parsed_articles (incident_status);
-- create index on parsed_articles (incident_status);
