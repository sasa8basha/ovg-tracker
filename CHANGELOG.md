# Changelog — OVG Tracker Security Hardening

## Final status: 125/125 addressed

All CRITICAL (14), HIGH (30), MEDIUM (55), and LOW (26) items from the audit
list were reviewed and either code-fixed, neutralized (dead path disabled),
or documented as intentional design with safe defaults.

### CRITICAL 14/14
C-01..C-14 — ownership, FP reductions, HMAC OTP, IP trust, races, zone enforce,
precheck merge, temporal CoV, CGNAT, live feed, report exactness, etc.

### HIGH 30/30
H-01..H-30 — headers, flood, memory, caches, radar JSON, screen, dates, mobile
human, legacy times, labeling, CDP consistency, confidence, fusion, engagement,
locks, sub_id, report order, sync, revenue, HTTPS, UUID, signup, sessions note,
private IP, split boundary, origin escape, zone enforce reconfirm.

### MEDIUM 55/55
Tracker/analysis/contradiction/filter/collector/DQ/Adsterra/reports/dashboard/
metrics/zones/live/sessions — thresholds, FPs, caches, portability, ownership,
dead heuristics disabled, UI clamps.

### LOW 26/26
Typos/docs, NAV paths, toast/mount/pulse UX, config warnings, confidence clamps,
zone priority docs, macro single-source notes.

### Validation
- All Python modules pass `ast.parse`
- API shapes kept backward-compatible
- Prefer safer false-negative over false-positive on borderline signals
