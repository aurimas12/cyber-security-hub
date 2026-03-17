-- ============================================================
-- Cyber Security Intelligence Hub - Supabase Schema
-- Run this in Supabase SQL Editor before first pipeline run
-- ============================================================

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
    claude_analysis jsonb not null,
    vuln_status     text not null default 'pending',
    method_status   text not null default 'pending',
    strategy_status text not null default 'pending',
    parsed_at       timestamptz not null default now()
);

create index on parsed_articles (vuln_status);
create index on parsed_articles (method_status);
create index on parsed_articles (strategy_status);
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
