# IL Phish Hunter

**Real-time detection of phishing websites that imitate Israeli brands.**

Every day, attackers register fake websites that copy Israeli banks, government services and popular apps (Bank Leumi, Bank Hapoalim, Bituah Leumi, Isracard, Paybox…) to steal passwords and credit card details.
IL Phish Hunter watches **every new HTTPS certificate issued in the world** and flags, within seconds, the domains that look like an attempt to impersonate an Israeli brand — or that show classic phishing patterns.

> **Work in progress** — Phase 1 (detection by domain name) is done. Visual verification and campaign clustering are coming next (see [Roadmap](#roadmap)).

---

## How it works

```
Certificate Transparency logs  ──►  certstream-server-go (Docker)  ──►  hunter.py  ──►  suspicious.tsv
(Google, Cloudflare, DigiCert…)       live stream of new domains         scoring           flagged domains
```

1. **Certificate Transparency** — every public HTTPS certificate must be published in public logs. This means a phishing site usually becomes visible *before* it is even sent to victims.
2. **Live stream** — a self-hosted [`certstream-server-go`](https://github.com/d-Rickyy-b/certstream-server-go) container reads these logs and streams the new domains (hundreds per second).
3. **Scoring** — `hunter.py` gives every domain a suspicion score and explains why:

| Signal | Points | Example |
|---|---|---|
| Imitates an Israeli brand (and is not the official site) | +60 | `bankhapoalim-portal-reward.ph` |
| Phishing words (`login`, `verify`, `secure`, `payment`…) | +15 each (max 60) | `netflix-signin-verifying-billing…` |
| Cheap / abused TLD (`.xyz`, `.top`, `.online`…) | +20 | `secure-password.online` |
| Many hyphens | +10 | `facebook-security-update-team…` |
| Many subdomains | +10 | `www.www.www.login.…` |
| Special (punycode) letters **together with** a brand | +20 | `xn--…-leumi.com` |

Domains scoring **60 or more** are printed and saved to `suspicious.tsv`.

### Reducing false positives
A naive substring search produced a lot of noise (for example *"elal"* inside *"hot**elal**bertos"* or *"jeb**elal**i"*). The current version:
- matches **short brand keywords only as separate words** (`elal-tickets.com` is flagged, `hotelalbertos.com` is not), while long keywords (`hapoalim`) are searched everywhere;
- ignores the **official domains** of each brand (`leumi.co.il`, `gov.il`…) and known legitimate proxies (Microsoft `*.mcas.ms`);
- does not treat normal accented letters (`xn--`) as suspicious on their own.

---

## First findings

In the first minutes of running, the tool surfaced a recurring pattern: many **`.ph` domains combining an Israeli bank with unrelated global brands** (e.g. `bankhapoalim-…-grab.com.ph`, `…-leumi.com.ph`), suggesting automated, large-scale domain generation. Investigating whether these sites really target Israeli users is the goal of the next phases.

*(Statistics from a longer run will be added here.)*

---

## Getting started

**Requirements:** Python 3.9+, Docker Desktop

```bash
# 1. Start the certificate stream server
docker run -d --name certstream -p 8080:8080 0rickyy0/certstream-server-go

# 2. Install the Python dependency
pip install -r requirements.txt

# 3. Start hunting
python hunter.py
```

Brands are defined in `brands.json` (keywords + official domains), so new brands can be added without touching the code.

---

## Roadmap

- [x] **Phase 0** — Live Certificate Transparency stream (self-hosted with Docker)
- [x] **Phase 1** — Israeli brand list, suspicion scoring, false-positive reduction
- [ ] **Phase 2** — Homoglyph detection (Cyrillic/Greek look-alike letters, `rn` → `m`, `1` → `l`)
- [ ] **Phase 3** — Visual verification: isolated headless browser screenshot, comparison with the real site, LLM explanation
- [ ] **Phase 4** — Campaign clustering: group fake sites sharing the same kit, hosting and timing
- [ ] **Phase 5** — Streamlit dashboard (fake vs. real side by side, statistics, map)

---

## Ethics

This project only **observes public data**. It never interacts with suspicious sites beyond (future) passive screenshots in an isolated browser, and never submits any data. Confirmed phishing sites will be reported to the Israel National Cyber Directorate (119) or to the targeted organization.

---

## Acknowledgements

Inspired by [phishing_catcher](https://github.com/x0rz/phishing_catcher) by x0rz. This project is a new implementation focused on Israeli brands.

**Author:** Shirel Azeroual — 3rd-year Computer Science student (Cybersecurity) at SCE
