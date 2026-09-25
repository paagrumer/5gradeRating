![ResearchGate](https://img.shields.io/badge/ResearchGate-Patrick%20Gruemer-blue?link=https://www.researchgate.net/profile/Patrick-Gruemer?ev=prf_overview)
![Automotive Project](https://img.shields.io/badge/Automotive-Project-blue)
![JavaScript](https://img.shields.io/badge/JavaScript-browser-f7df1e.svg)
![No installation](https://img.shields.io/badge/Runs%20in-any%20browser-brightgreen.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Cybersecurity Researcher](https://img.shields.io/badge/Role-Cybersecurity%20Researcher-blue)

# 🛡️ Automotive Cybersecurity Rating Framework

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <img src="car.png" alt="car" width="220" height="220">
</p>

A browser-based implementation of a five-star rating that expresses the **residual vulnerability exposure** of automotive components and vehicles, grounded in the methodologies from:

- 📄 [An Automotive Cybersecurity Maturity Level Assessment Programme (2023)](https://www.researchgate.net/publication/372140215)
- 📄 [Computing an Automotive Cybersecurity Maturity Level Assessment Programme (2024)](https://www.researchgate.net/publication/376231070)
- 📄 Automotive Cybersecurity Rating (journal article, under review at IEEE Access)

---

## 🚀 Overview

Cybersecurity will be key for new and future vehicles, which depend on the exchange of data with the infrastructure. These vehicles bring countless new features and are potentially capable of autonomous driving. This repository provides the interactive web tool and the fleet simulator behind the research above. It lets anyone rate a vehicle and its components on a clear scale, and study how that rating behaves across whole fleets. The aim is a trustworthy and reliable environment for these technologies, built on the standards the industry already uses for secure development and security assessment.

Think of it as Euro NCAP, but for cybersecurity rather than crash safety.

## ⭐ What the rating is

The framework gives a vehicle a cybersecurity rating on a scale of **0 to 5 stars**, reported to two decimal places. The rating is built from the ECUs inside the car, the small computers that run braking, the engine, infotainment and the doors. Each ECU is scored on its own, and those scores are combined into a single figure for the whole vehicle. Every step rests on international standards (ISO/SAE 21434, ISO 26262 and CVSS), so two assessors given the same inputs reach the same result.

**Component Stars.** Each ECU undergoes a structured penetration testing campaign whose depth scales with its ASIL. Its **star score** comes from the CVSS severity of the confirmed findings: findings are grouped by category, the worst finding in each category is kept, and the three worst categories set the score. A clean ECU scores a full 5.00. Any confirmed finding caps the score at 4.75, and a finding of CVSS 7.0 or higher halts the assessment until it is fixed and re-tested.

**Vehicle Stars.** Each ECU also carries a **weight** that reflects how critical and exposed it is. The weight comes from Table H.8 of ISO/SAE 21434, where the **impact** (from the ASIL, raised one level if the ECU handles personal data) meets the **attack feasibility** (from the CVSS exploitability of its findings, adjusted for network reach and for a proven segmentation gateway). The vehicle rating is the weighted average of the star scores:

```
R = Sum(star score x weight) / Sum(weight)
```

A weakness in a high-weight ECU pulls the rating down sharply, while the same weakness in a low-weight ECU barely moves it. The star score of every ECU is reported alongside `R`, so a single weak component remains visible and cannot be averaged away unnoticed.

**What the rating is not.** It is a point-in-time observation of residual vulnerability exposure against a defined test campaign. It does not measure organisational maturity, process quality or resistance to unknown attacks. A 5.00 means no finding was recorded in the tested set on that date, not that the component has no vulnerabilities.

| Stars | | Meaning |
|---|---|---|
| 5 | ★★★★★ | No finding recorded in the tested campaign (exactly 5.00) |
| 4 | ★★★★☆ | Minor residual findings |
| 3 | ★★★☆☆ | Moderate residual exposure |
| 2 | ★★☆☆☆ | Significant residual exposure |
| 1 | ★☆☆☆☆ | High residual exposure |
| 0 | ☆☆☆☆☆ | Severe residual exposure |

A finding of CVSS 7.0 or higher produces no rating at all: the assessment halts and mitigation is mandated.

## 🧠 High-level view of the rating framework

![image](https://github.com/user-attachments/assets/1dd12d54-c210-4cbb-a520-4dcfd454195c)

## 🖥️ Interactive web tool (no installation)

The quickest way to explore the framework is the web tool. It needs no installation and no dependencies.

- **Open it directly.** Download `standalone.html` from this repository and open it in any modern browser. Everything runs locally in the page.
- **Or launch the hosted copy.** If GitHub Pages is enabled for this repository, the tool is served at `https://paagrumer.github.io/5gradeRating/standalone.html`.

The tool has six tabs:

- **Architecture** shows how the same ECUs are reorganised across distributed, domain and zonal vehicle generations.
- **Non-technical** explains the rating in plain language for managers, regulators and consumers.
- **Technical** documents every rule, formula and design decision, with the standard it comes from.
- **Simplified example** rates one reference vehicle end to end, with every CVE linked to its NVD record, so the Component Stars and Vehicle Stars can be checked by hand.
- **Simulator** generates thousands of synthetic vehicles and reports how the rating is distributed across the fleet. **Reset to paper** loads the exact configuration from the journal.
- **Verification & Validation** runs the automated test suite live, so the rules can be checked the moment the page loads.

## 🏗️ How it is built

The tool ships in two equivalent forms. Both run the identical model in any modern browser.

- **`standalone.html`** is a single self-contained file with everything inlined. Open it or share it as is.
- **`index.html` plus its modules** is the same tool split into files for readability. Keep the files together in one folder and open `index.html`.

`standalone.html` is the inlined version of `index.html` and its modules, so the two are functionally identical. The modules load in a fixed order (config, ui, architecture, rating, simulation), because each one builds on the previous.

## 📁 File Structure

```bash
├── standalone.html   # Single self-contained tool (open in a browser)
├── index.html        # The same tool, loads the modules below
├── config.js         # Every number and rule input: ECUs, categories, ASIL to impact, Tables G.8 and H.8, shifts, gateway credit, thresholds, simulator defaults
├── ui.js             # Tab navigation
├── architecture.js   # The vehicle architecture diagrams
├── rating.js         # Component star score, weights, gateway credit, vehicle rating and their tests
├── simulation.js     # Fleet simulator, statistics, charts and CSV exports
├── car.png
├── README.md
```

## 🔁 Reproducing the published results

Every number in the journal article can be reproduced from this tool.

| Result | Where to find it | Expected value |
|---|---|---|
| Reference vehicle rating | Simplified example | `R = 90.32 / 28 = 3.23` over 19 cybersecurity-relevant ECUs (25 in total) |
| Typical modern vehicle fleet | Simulator, **Reset to paper**, seed `21434`, 10,000 vehicles | mean `3.65`, median `3.65`, standard deviation `0.48`, min `1.86`, max `5.00` |
| Rule checks | Verification & Validation | all automated checks pass |

Runs are seeded with a single random generator (mulberry32), so the same settings and seed reproduce the same fleet exactly. The seed is written into every CSV export.

## 🚗 Configuration

The simulator is driven by the settings below, all defined in `config.js` under `simulation`. The simulator treats every generated component as cybersecurity-relevant.

| Variable | Description |
|---|---|
| `vehicles` | Number of vehicles in the simulated fleet (at least 1). |
| `ecuCount` | Number of ECUs per vehicle, from 0 to 100. |
| `domainProbability` | Share of ECUs per domain, summing to 100%. |
| `asilByDomain` | Share of QM, A, B, C and D within each domain. |
| `netInteractionByDomain` | Share of the four network-interaction levels within each domain. |
| `gatewayByDomain` | Share of whitelist, blacklist and no gateway within each domain. |
| `piaProbability` | Probability that a component handles personal data. |
| `vulnProbMode` | How the vulnerability probability is set: `manual`, `features` (derived from the selected security features) or `featuresRandom` (a seeded random feature set per vehicle). |
| `vulnProbability` | Probability that a component carries findings. Either 0 (a perfect fleet, every vehicle scores 5.00) or at least 5%, since a residual risk below 5% cannot be claimed once a weakness is possible. |
| `securityFeatures` | Catalogue of mitigations (secure boot, HSM, SecOC, IDS and others). Starting from 100% for an unsecured ECU, each enabled feature lowers the vulnerability probability, down to a floor of 5%. The weights are illustrative and pending industry calibration. |
| `vulnRange` | Lower and upper CVSS base score for generated findings, drawn from the achievable CVSS v3.1 scores in that interval. The upper bound is at most 6.9, because 7.0 or higher halts the assessment. |
| `findingsPerEcu` | Number of findings per vulnerable ECU, for example 1 to 3. |
| `seed` | Seed of the random generator. The same seed and settings reproduce the same fleet. |

## Component Domains

Each ECU belongs to a domain. The domain mix sets the share of ECUs drawn from each domain when a fleet is generated.

| Domain | Description |
|---|---|
| ADAS | Advanced Driver Assistance Systems. |
| Powertrain | Engine, transmission and related systems. |
| HMI | Infotainment, driver controls and related systems. |
| Body | Doors, climate control, lighting and related systems. |
| Chassis | Suspension, steering, braking and related systems. |

## 📐 The rules

### Component star score

1. Group the confirmed findings by category (Networks, Software, Cryptography, Diagnostics, Physical, Access-Control) and keep only the worst CVSS in each category.
2. Sort the categories worst first and keep the top three: `C0`, `C1`, `C2`.
3. Combine them into `X`:
   - any finding of 7.0 or higher: **critical**, the assessment halts and no score is given
   - any finding from 5.3 to 6.9: **worst case**, `X = C0`
   - all findings below 5.3: one category `X = C0`, two categories `X = 0.6 C0 + 0.4 C1`, three categories `X = 0.6 C0 + 0.3 C1 + 0.1 C2`
4. The star score is `s = -0.725 X + 5`, clamped to `[0, 5]`. A clean component scores `5.00`, and any finding caps it at `4.75` (the 5% residual rule).

### Impact from ASIL

The ASIL of a component sets the **impact rating** (the row of Table H.8). ISO/SAE 21434 derives impact from four categories (safety, financial, operational and privacy). The framework anchors it on safety through the ASIL, because the ASIL is a single value that persists to vehicle integration and is recorded in the safety case.

| ASIL Level | Impact rating |
|---|---|
| QM | Negligible |
| A | Moderate |
| B | Major |
| C | Severe |
| D | Severe |

### Privacy shift (PIA)

The privacy impact is a **binary** check: a component either handles personal data or it does not. Where it does, its impact rating rises by one level, capped at Severe. This carries the privacy impact category of ISO/SAE 21434 and aligns with the data protection impact assessment of GDPR Article 35.

| PIA | Effect on impact |
|---|---|
| No personal data | No change. |
| Handles personal data | Impact rating raised by one level, capped at Severe. |

### Attack feasibility from CVSS (Table G.8)

Following [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html) Annex G.3, attack feasibility is read from each finding's own CVSS vector, so two independent assessors reach the same value:

```
E = 8.22 x AV x AC x PR x UI
```

where `AV`, `AC`, `PR` and `UI` are the CVSS exploitability metrics (attack vector, attack complexity, privileges required and user interaction), with the numerical values defined in the [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3-1/specification-document). `E` ranges from 0.12 to 3.89. With several findings, the `E` values of the same three worst categories are combined with the same weights as the star score. Table G.8 maps `E` to an **attack feasibility rating**:

| Attack feasibility rating | CVSS exploitability value |
|---|---|
| High | 2.96 to 3.89 |
| Medium | 2.00 to 2.95 |
| Low | 1.06 to 1.99 |
| Very low | 0.12 to 1.05 |

The ratings and ranges are taken verbatim from ISO/SAE 21434:2021, Table G.8.

**Findings gate.** A component with no confirmed finding has no demonstrated exploit, so it stays at **Very Low** feasibility. Neither the network-interaction shift nor the gateway credit applies to it, and its weight follows its impact alone.

### Network-interaction shift

For a component with a finding, the feasibility rating is shifted by how far a compromise can reach across the vehicle network. The level is read from the vehicle communication matrix.

| Level (`netInteraction`) | Shift | Meaning |
|---|---|---|
| `Iso` | +0 | Isolated, no communication beyond its own boundaries. |
| `E-E` | +0 | ECU-to-ECU, communicates only within its own domain. |
| `E-D` | +1 | ECU-to-Domain, communicates across domain boundaries. |
| `E-C` | +2 | ECU-to-Connectivity, reaches an externally connected domain. |

The shifted rating is capped at **High**.

### Gateway mitigation credit

A segmentation gateway recorded in the component's TARA lowers the exposed feasibility. The credit is scaled by ASIL:

| Gateway | QM | A | B | C | D |
|---|:-:|:-:|:-:|:-:|:-:|
| Whitelist | 0 | 1 | 1 | 2 | 2 |
| Blacklist | 0 | 0 | 0 | 1 | 1 |
| None | 0 | 0 | 0 | 0 | 0 |

Three rules keep the credit from overstating the protection:

- it is **capped at the interaction shift**, so it only removes the exposure the network added, and Isolated and ECU-to-ECU components receive none
- it is **floored at the base feasibility**, so it never places a finding below the band of its own CVSS exploitability
- it is **findings-gated**, so it applies only to components with a confirmed finding

### Weight (Table H.8)

The impact rating (rows) and the final attack feasibility rating (columns) meet in the risk matrix of [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html), Table H.8, which gives the component **weight** `w` in `[1, 5]`:

| Impact rating \ Attack feasibility rating | Very Low | Low | Medium | High |
|---|:-:|:-:|:-:|:-:|
| Severe | 2 | 3 | 4 | 5 |
| Major | 1 | 2 | 3 | 4 |
| Moderate | 1 | 2 | 2 | 3 |
| Negligible | 1 | 1 | 1 | 1 |

### Vehicle rating

```
R = Sum(s x w) / Sum(w)
```

over the cybersecurity-relevant components, where `s` is each component's star score and `w` its weight. Components flagged critical are reported and held out of the average.

## ▶️ Using the simulator

Open `standalone.html` (or `index.html`) and go to the **Simulator** tab. Set the fleet size, the ECUs per vehicle, the domain, ASIL, interaction and gateway mixes, the PIA probability, the vulnerability probability (manually or from the security features), the CVSS range and the seed, then run. **Reset to paper** restores the typical modern vehicle from the journal.

Results can be exported as CSV, one row per vehicle or one row per component. Because runs are seeded, the same settings and seed reproduce the same fleet every time.
