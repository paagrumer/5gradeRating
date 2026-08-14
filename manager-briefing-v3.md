# Vehicle Cybersecurity Star Rating — Management Briefing (v3)

**A plain-language guide to how we score the cybersecurity of a whole vehicle.**
No cybersecurity background required. Think of it as "Euro NCAP, but for hacking."

*What changed since v2: the "how easy to attack" score is now read straight from the real vulnerabilities we find, not estimated from the car's layout. That removes the last place where human judgement crept in — the exact criticism our reviewers raised.*

---

## 1. The idea in one paragraph

Euro NCAP gives a car a crash-safety star rating any buyer understands. We do the same for cybersecurity: a rating from **1 to 5 stars**, more stars = better protection against hacking. It is built from the small computers inside the car — the ECUs that run brakes, engine, infotainment, doors. Each ECU is tested and scored, then combined into one number for the whole vehicle. Every step rests on international standards the industry already uses, so the result is objective and repeatable — not opinion.

---

## 2. Why we need it

- A modern car has 25–150+ networked computers; any one can be an attacker's door.
- UN Regulation No. 155 now **requires** manufacturers to manage cybersecurity across the whole vehicle lifecycle.
- There is no simple, comparable way today to tell a buyer, fleet operator, or regulator "how secure is this vehicle."
- Our framework gives that single, understandable number, on standards the industry already trusts.

---

## 3. Each ECU gets a security "stamp" from real testing

Every ECU is put through **automated penetration testing** — controlled, simulated attacks grouped into categories (Networks, Diagnostics, Software, …). The stamp (1–5) comes from two facts about the real weaknesses we find, both read from standard, published data — nothing estimated:

- **How bad would it be if this weakness were exploited?** (the *impact*) — from the car industry's own safety scale (ASIL), plus a privacy check. Brakes/steering = high impact; a lamp = negligible.
- **How achievable is the attack?** (the *feasibility*) — read **directly from the vulnerability's own CVSS record** (the industry-standard vulnerability score). An internet-reachable, easy-to-exploit weakness scores high; one needing physical access and special privileges scores low.

These two meet in a table taken straight from the standard (ISO/SAE 21434, Table H.8), which gives the ECU's risk, and the stamp is simply `6 − risk`:

- **Stamp 5** = no significant weakness found.
- **Lower stamp** = the worse the weakness, the lower the stamp.
- A **critical** finding (top of the risk table) **halts the ECU**: it cannot be rated until fixed and re-tested — no way to hide a serious weakness.

**Why this is stronger than v2.** In v2 the "how achievable" number was estimated from the car's layout (network segmentation, attacker position). Now it is read off the actual vulnerability's published record, so two independent assessors get the identical answer. The "communication exposure" question is already built into that record, so we no longer add it by hand.

---

## 4. Each ECU also gets a "weight" — how much it matters

Not every ECU matters equally: a brake controller matters far more than a reading lamp. So each ECU carries a **weight** reflecting how important it is to protect. The weight comes from the same standards-based impact scale (how bad if it were hacked): Severe > Major > Moderate > Negligible. A brake controller weighs most; a lamp weighs least. The weight exists for every ECU, whether or not any weakness was found — because an important component matters even when it tests clean.

---

## 5. Combining stamps and weights into the vehicle stars

The vehicle rating is a **weighted average** — each ECU's stamp counts in proportion to its weight:

```
Vehicle stars = Σ (stamp × weight) for every ECU
                ---------------------------------
                     Σ (weight) for every ECU
```

- A weakness in a **high-weight** ECU (e.g. a connected brake controller) pulls the rating down a lot.
- The same weakness in a **low-weight** ECU (an isolated lamp) barely moves it.
- ECUs with no cybersecurity role are left out entirely.

We also publish a **conservative "floor"** — the rating the vehicle's single weakest important ECU would give on its own. If the headline average and the floor diverge a lot, that gap is itself flagged. This directly answers a reviewer concern that an average can hide one bad component.

| Stars | Meaning |
|---|---|
| 5 | Excellent protection |
| 4 | Strong protection |
| 3 | Adequate, some concerns |
| 2 | Weak, significant concerns |
| 1 | Poor, major exposure |

---

## 6. A worked example (numbers that reconcile exactly)

Three ECUs: a connected **brake** (weight 4) with a moderately-exploitable finding → stamp 2; an **infotainment** unit (weight 2) with a similar finding → stamp 4; a clean **lamp** (weight 1) → stamp 5.

`Vehicle = (2×4 + 4×2 + 5×1) / (4 + 2 + 1) = 21 / 7 = 3.0 stars.` Floor = 2 stars (the brake).

The brake dominates; the lamp is almost invisible — the framework spotlighting the components that can actually cause harm. (Reviewers flagged an arithmetic mismatch in the old paper; the new structure makes every published number reproduce to the digit.)

---

## 7. Handling change over time (not a one-off)

- **Software updates (UN R156):** an update that changes an ECU's security posture triggers re-testing and a fresh vehicle rating — the rating is tied to a specific software version.
- **New vulnerabilities (UN R155):** a newly disclosed weakness relevant to a component triggers re-scoring through our incident-response process.
- **Periodic renewal:** like Euro NCAP, ratings expire and must be renewed; more critical components are reviewed more often.

---

## 8. How the shared vulnerability database is governed (reviewer concern)

The rating depends on a shared, industry-maintained attack database (the ACODB). To be credible it needs, and our proposal specifies: a defined **update cycle**; **validation** of submitted attacks before they count; **provenance/authenticity** checks on supplier-contributed data; and **protection of sensitive security information** (need-to-know access, so publishing a rating never exposes an exploit). Each rating also records which database version and test set produced it, so any result can be re-derived later.

---

## 9. Why managers can trust it

- **Evidence-based:** stamps come from real automated penetration testing — measured vulnerabilities.
- **Standards-based, not opinion-based:** impact, feasibility, and the combining table all come from ISO/SAE 21434, ISO 26262, and CVSS.
- **Repeatable:** two independent assessors get the same result — now including the feasibility number, which is read from published data.
- **Transparent:** for every ECU you can see the vulnerabilities found, their CVSS records, the impact, the weight, and how much each moved the final number.
- **Actionable:** it shows exactly which ECUs drag the rating down — usually high-weight, connected safety components — so budget goes where it matters.
- **Regulation-aligned:** tied to a software version (R156) and to lifecycle risk management (R155).

---

## 10. What it is — and what it is not

**It is:** a clear, comparable, standards-based measure of a vehicle's cybersecurity **risk condition at a point in time**, built from real detected vulnerabilities weighted by how much each component matters.

**It is not:** a guarantee a vehicle can never be hacked, a measure of development-process maturity, or a substitute for the full engineering and regulatory processes. A clean ECU scores 5 because *no weakness was found in the tested set at that date* — a bounded, checkable claim, not a promise of perfect security. (We now say "security rating," not "maturity," to match exactly what is measured.)

---

## 11. One-sentence summary for a slide

> Each ECU earns a security stamp from real penetration testing — impact from safety standards, feasibility read straight from the vulnerability's own CVSS record — and a weight for how much it matters; the vehicle's 1–5 star rating is the weighted average, with a worst-case floor. Objective, repeatable, standards-based, and understandable by anyone.

---

## 12. Talking points for the meeting

- "The score isn't our opinion — impact comes from safety standards, and how-easy-to-attack is now read directly from each vulnerability's published record."
- "We fixed the one place judgement crept in: feasibility used to be estimated from the car's layout; now it's data from the finding itself."
- "High-weight, connected safety components dominate the score — exactly where we should invest first."
- "A single critical finding halts the component until it's fixed. Nothing serious can be hidden."
- "We publish both the average and a worst-case floor, so one bad ECU can't be averaged away unnoticed."
- "It's reproducible: same vehicle, same version, same database — same number."

---

*Companion materials: the interactive web tool and the Python simulator reproduce these rules. Both must be updated to v9 — the feasibility input now takes each finding's CVSS vector instead of estimating from architecture.*
