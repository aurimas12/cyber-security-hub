# Milestone 1 — Veikianti Duomenų Surinkimo ir Analizės Sistema

**Tikslas:** Pilnai automatizuotas pipeline kuris savarankiškai renka, analizuoja ir validuoja kibernetinio saugumo žvalgybą be rankinio įsikišimo.

---

## 1. Infrastruktūra ir CI/CD

- [x] Supabase projektas sukurtas
- [x] Visos DB lentelės sukurtos (`schema.sql` paleista)
- [x] pgvector extension įjungtas
- [x] GitHub Actions `pipeline.yml` — collect → parse → extract → eval
- [x] GitHub Actions `backfill.yml` — kasdien 01:30 UTC
- [x] Visi GitHub Secrets sukonfigūruoti (`SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `GEMINI_API_KEY`, `NVD_API_KEY`)
- [ ] Pipeline sėkmingai paleistas GitHub Actions bent 3 kartus iš eilės be klaidų

---

## 2. Duomenų Surinkimas

- [x] `news_collector.py` — 16 RSS šaltinių
- [x] `nvd_api_collector.py` — NVD 2.0 API su paginacija
- [x] Deprecated NVD RSS pašalintas
- [x] 403 begalinė kilpa pataisyta (max retries)
- [ ] Visi 16 RSS šaltiniai grąžina duomenis (patikrinti `raw_articles` lentelėje)
- [ ] NVD API grąžina CVE duomenis (`source_feed = 'nvd_api'`)
- [ ] `raw_articles` sukaupė >500 straipsnių

---

## 3. RAG — MITRE ATT&CK Paieška

- [x] `mitre_techniques` lentelė sukurta su `vector(768)`
- [x] `match_mitre_techniques()` SQL funkcija
- [x] HNSW indeksas ant embedding stulpelio
- [x] `setup_mitre_embeddings.py` — 691 technika su `fastembed`
- [x] `article_parser.py` — RAG lookup prieš kiekvieną Gemma kvietimą
- [x] RAG kandidatai įrašomi į `ai_analysis.rag_candidates`
- [ ] `setup_mitre_embeddings.py` sėkmingai paleistas (691 eilutė `mitre_techniques`)
- [ ] Patikrinta kad `parsed_articles.ai_analysis` turi `rag_candidates` lauką

---

## 4. AI Parserinimas

- [x] `article_parser.py` — Gemma 3-12B via Google AI Studio
- [x] System prompt su few-shot pavyzdžiu
- [x] JSON retry logika pataisyta (veikia iki MAX_RETRIES)
- [x] Daily budget guard (sustoja ties 950/1000 RPD)
- [x] `DELAY_BETWEEN_REQ = 2.5s` — saugus RPM limitas
- [ ] `parsed_articles` turi >100 eilučių
- [ ] `ai_analysis` JSON struktūra teisinga (visi 5 laukai: vulnerabilities, techniques, recommendations, threat_actors, incidents)
- [ ] Nėra straipsnių stuck `processing` statusu po 24h

---

## 5. Duomenų Išskyrimas

- [x] `vuln_extractor.py` → `vulnerabilities`
- [x] `methodology_extractor.py` → `methodologies` + `review_queue`
- [x] `strategy_extractor.py` → `strategies`
- [x] `threat_actor_extractor.py` → `threat_actors`
- [x] `incident_extractor.py` → `incidents`
- [x] Visi extractoriai su `.order("parsed_at")` — FIFO eilė
- [x] `backfill.py` atnaujina visus 5 statusus
- [ ] Visos 5 lentelės turi duomenų
- [ ] `review_queue` turi eilučių (Gemma neradusių MITRE atitikties)

---

## 6. Kokybės Kontrolė

- [x] `eval.py` — MITRE ID tikrinimas prieš MITRE CTI GitHub
- [x] `ai_validations` lentelė saugo rezultatus
- [x] CVE ID tikrinimas prieš NVD API
- [x] `mitre_id_format_ok()` regex validacija
- [ ] `ai_validations` turi >50 eilučių
- [ ] MITRE accuracy >60% (bent 60 iš 100 ID egzistuoja ATT&CK)
- [ ] CVE accuracy >80% (NVD patvirtina didžiąją dalį)

---

## 7. Testai

- [x] `tests/` direktorija su 7 testų failais
- [x] `conftest.py` su `FakeTable` ir `make_mock_db`
- [x] `test_article_parser.py` — 14 testų
- [x] `test_news_collector.py` — 10 testų
- [x] `test_nvd_api_collector.py` — 12 testų
- [x] `test_extractors.py` — 16 testų
- [x] `test_backfill.py` — 8 testų
- [x] `test_eval.py` — 20 testų
- [x] `test_setup_mitre_embeddings.py` — 10 testų
- [ ] Visi ~110 testų praeina (`pytest tests/ -v`)
- [ ] Testai pridėti į GitHub Actions pipeline

---

## 8. Dokumentacija

- [x] `README.md` — atnaujintas (GEMINI_API_KEY, 16 šaltinių)
- [x] `docs/architecture.md` — pilna Mermaid diagrama
- [x] `SECURITY.md` — saugumo politika
- [x] `supabase/schema.sql` — pilna schema su komentarais
- [ ] `plans/nvd_api_migration_plan.md` — pažymėti kaip užbaigta

---

## Milestone 1 Sėkmės Kriterijai

Pipeline turi automatiškai (be rankinio įsikišimo):

1. Kas 6 valandas surinkti naujus straipsnius iš 16 šaltinių + NVD
2. Apdoroti su Gemma + RAG MITRE paieška
3. Išskirti duomenis į 5 lenteles
4. Validuoti MITRE ir CVE ID tikslumą
5. Automatiškai atkurti klaidas (backfill)

**DB metrics po 1 savaitės veikimo:**
- `raw_articles` > 1,000 eilučių
- `parsed_articles` > 500 eilučių
- `vulnerabilities` > 200 eilučių
- `methodologies` > 300 eilučių
- `ai_validations` > 100 eilučių
- `review_queue` > 0 eilučių (sistema veikia ir identifikuoja problemas)

---

## Milestone 2 (ateityje)

- Analytics dashboard (Supabase + frontend)
- Alertai kritiniams CVE (CVSS >= 9.0)
- Kanoninis CVE ir threat actor deduplication
- HTML stripping preprocessing (`trafilatura`)
- Fine-tuning arba Groq Llama 3.3 70B kaip alternatyva
