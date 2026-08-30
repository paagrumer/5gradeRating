![ResearchGate](https://img.shields.io/badge/ResearchGate-Patrick%20Gruemer-blue?link=https://www.researchgate.net/profile/Patrick-Gruemer?ev=prf_overview)
![Automotive Project](https://img.shields.io/badge/Automotive-Project-blue)
[![Python 3.12.2](https://img.shields.io/badge/python-3.12.2-blue.svg)](https://www.python.org/downloads/release/python-3122/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Cybersecurity Researcher](https://img.shields.io/badge/Role-Cybersecurity%20Researcher-blue)

# 🛡️ Automotive Cybersecurity Maturity Assessment Framework

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <img src="car.png" alt="car" width="220" height="220">
  </a>

A Python-based implementation of a five-grade maturity model for assessing cybersecurity capabilities in the automotive sector, grounded in the methodologies from:

- 📄 [An Automotive Cybersecurity Maturity Level Assessment Programme (2023)](https://www.researchgate.net/publication/372140215)
- 📄 [Computing an Automotive Cybersecurity Maturity Level Assessment Programme (2024)](https://www.researchgate.net/publication/376231070)

---

## 🚀 Overview
Cybersecurity will be key for the new and future vehicles that depend on the exchange of data with the infrastructure. These vehicles will bring countless new features and are potentially capable of autonomous driving. This repository provides the interactive web tool and the Python fleet simulator behind the research above. The goal is to let anyone rate the cybersecurity quality of a vehicle and its components on a clear scale, and to study how that rating behaves across whole fleets. The objective is to establish a trustable and reliable environment for these advanced technologies. Based on the standards used for secure software development and security assessment, we defined a procedure for the evaluation of the security of the technological components of a car.

Think of it as Euro NCAP, but for cybersecurity rather than crash safety.

## ⭐ What the rating is

The framework gives a vehicle a cybersecurity rating on a scale of **0 to 5 stars**, reported to two decimal places. More stars mean better protection. The rating is built from the ECUs inside the car, the small computers that run braking, the engine, infotainment and the doors. Each ECU is scored on its own, and those scores are combined into a single figure for the whole vehicle. Every step rests on international standards the industry already uses (ISO/SAE 21434, ISO 26262 and CVSS), so the result is objective and repeatable rather than a matter of opinion.

**How Component Stars work.** Each ECU earns a **star score** from the real vulnerabilities found in it. Two facts about each finding decide the score, both read from standard published data. The **impact** (how serious exploitation would be) comes from the automotive safety scale (ASIL, from ISO 26262), with a privacy check. The **feasibility** (how achievable the attack is) is read directly from the vulnerability's own CVSS record. Impact and feasibility meet in Table H.8 of ISO/SAE 21434, which sets the ECU's risk. A clean ECU scores a full 5.00, any confirmed vulnerability lowers the score towards 0, and a critical finding halts the ECU until it is fixed and re-tested.

**How Vehicle Stars work.** Each ECU also carries a **weight** for how important it is to protect, so a braking controller counts far more than a courtesy lamp. The vehicle rating is the weighted average of the star scores, `Vehicle Stars = Sum(star score x weight) / Sum(weight)`. A weakness in a high-weight ECU pulls the rating down sharply, while the same weakness in a low-weight ECU barely moves it. Alongside the average, a conservative floor reports what the single weakest important ECU would give on its own, so one poor component cannot be averaged away unnoticed.

| Stars | Meaning |
|---|---|
| 5 | Excellent protection |
| 4 | Strong protection |
| 3 | Adequate, some concerns |
| 2 | Weak, significant concerns |
| 1 | Poor, major exposure |
| 0 | Critical exposure, no effective protection |

## 🧠 High-level view of the 5-grade framework

![image](https://github.com/user-attachments/assets/1dd12d54-c210-4cbb-a520-4dcfd454195c)

## 🖥️ Interactive web tool (no installation)

The quickest way to explore the framework is the self-contained web tool. It needs no installation and no dependencies.

- **Open it directly.** Download `standalone.html` from this repository and open it in any modern browser. Everything runs locally in the page.
- **Or launch the hosted copy.** If GitHub Pages is enabled for this repository, the tool is served at `https://paagrumer.github.io/5gradeRating/standalone.html`.

Inside the tool you can:

- **Architecture** shows how the same ECUs are reorganised across distributed, domain and zonal vehicle generations.
- **Simplified example** works one representative vehicle end to end, with every CVE linked to its NVD record, so the Component Stars and Vehicle Stars can be checked by hand.
- **Simulator** generates thousands of synthetic vehicles and reports how the rating is distributed across the fleet. Runs are seeded and reproducible. **Reset to paper** loads the exact example from the journal, so the published rating can be reproduced directly.
- **Ver&Val** runs the unit and integration tests live, so the rules can be checked the moment the page loads.

## 🏗️ How it is built

The tool ships in two equivalent forms. Both run the identical model in any modern browser, with no installation and no dependencies. Clone or download the repository, then open one of them.

- **`standalone.html`** is the base: a single self-contained file with everything inlined. Open it or share it as is. This is the simplest way to run the tool.
- **`index.html` plus its modules** is the same tool split into files for a clean, readable architecture. Keep the files together in one folder and open `index.html`.

`standalone.html` is simply the built, inlined version of `index.html` and its modules, so the two are functionally identical. The modules exist for readability and segmentation: edit them for clarity, then inline them into `standalone.html` for distribution.

## 📁 File Structure

```bash
├── standalone.html   # The base: single self-contained tool (open in a browser)
├── index.html        # The same tool, loads the modules below
├── config.js         # Data and rules: ECUs, categories, ASIL to impact, Table H.8 and G.8, the shift, thresholds
├── rating.js         # Component star score (Algorithm 1) and the vehicle rating
├── simulation.js     # Fleet simulator, charts and CSV exports
├── architecture.js   # The vehicle architecture diagrams
├── ui.js             # Tab navigation and app wiring
├── car.png
├── README.md
```

## 🚗 Configuration and rules

The simulator inside the tool is driven by the settings below, and every rating follows the rules that follow.

## Fleet and ECU Configuration

| Variable          | Description |
|-------------------|-------------|
| `numberVehicles`  | Number of vehicles in the simulated fleet. |
| `ecusPerVehicle`  | Number of ECUs (Electronic Control Units) per vehicle. |
| `vulnProbability` | Probability that a component carries a vulnerability. It is either 0 (a perfect fleet, every component scores 5.00) or at least 5%, since under-5% uncertainty cannot be claimed once a weakness is possible. |
| `minCVSS`, `maxCVSS` | Lower and upper CVSS base score for generated findings. Both are capped below 7.0, because a CVSS of 7 or higher is treated as critical and handled separately. |
| `piaProbability`  | Probability that a component handles personal data, which raises its impact by one level (the privacy shift). |
| `seed`            | Seed for reproducibility (`0` for a random seed). |

---

## Component Domains

Each ECU belongs to a domain. The domain mix sets the share of ECUs drawn from each domain when a fleet is generated.

| Domain     | Description |
|------------|-------------|
| ADAS       | Advanced Driver Assistance Systems. |
| Powertrain | Engine, transmission, and related systems. |
| HMI        | Infotainment, driver controls, and related systems. |
| Body       | Doors, climate control, lighting, and related systems. |
| Chassis    | Suspension, steering, braking, and related systems. |

---

## Impact from ASIL

The ASIL of a component sets the **impact rating** of the [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html) risk matrix, derived from the safety classification of ISO 26262. The impact ratings are Negligible, Moderate, Major and Severe.

| ASIL Level | Impact rating |
|------------|---------------|
| QM         | Negligible |
| A          | Moderate |
| B          | Major |
| C          | Severe |
| D          | Severe |

## Privacy shift (PIA)

The privacy impact is a **binary** check: a component either handles personal data or it does not. Where it does, its impact rating rises by one, capped at Severe. This carries the privacy impact category of the [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html) impact assessment and aligns with the data-protection impact assessment of GDPR Article 35.

| PIA | Effect on impact |
|-----|------------------|
| No personal data | No change. |
| Handles personal data | Impact rating raised by one, capped at Severe. |

## Attack feasibility from CVSS (Table G.8)

Attack feasibility is not estimated from the vehicle layout. Following [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html) Annex G.3, it is read directly from each finding's own CVSS record, so two independent assessors reach the same value. The standard gives the exploitability value as

```
E = 8.22 x V x C x P x U
```

where `V`, `C`, `P` and `U` are the CVSS base exploitability metrics (attack vector, attack complexity, privileges required and user interaction). `E` ranges from 0.12 to 3.89, and Table G.8 of the standard maps it to an **attack feasibility rating**:

| Attack feasibility rating | CVSS exploitability value |
|---------------------------|---------------------------|
| High                      | 2.96 to 3.89 |
| Medium                    | 2.00 to 2.95 |
| Low                       | 1.06 to 1.99 |
| Very low                  | 0.12 to 1.05 |

The ratings and ranges are taken verbatim from [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html), Table G.8 (example CVSS exploitability mapping).

---

## Network-interaction shift (shift mode)

The earlier interaction risk map is replaced by a **network-interaction shift**. Instead of estimating interaction risk by component type, the attack feasibility rating is shifted by how far a component can reach across the vehicle network. This keeps the connectivity question inside the CVSS-driven feasibility rather than adding a separate hand-set judgement.

| Reach (`netInteraction`) | Shift | Meaning |
|--------------------------|-------|---------|
| `Con`                    | +0    | Contained, no onward network reach. |
| `E-E`                    | +0    | End-to-end within its own domain. |
| `E-D`                    | +1    | Reaches an adjacent domain. |
| `E-C`                    | +2    | Reaches the external / connectivity domain. |

The shifted band is capped at **High**.

## Combining impact and attack feasibility (Table H.8)

The impact rating (rows) and the shifted attack feasibility rating (columns) meet in the risk matrix, Table H.8 of [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html), which gives the component **weight** `w` in `[1, 5]`:

| Impact rating \ Attack feasibility rating | Very Low | Low | Medium | High |
|--------------------------------------------|:--------:|:---:|:------:|:----:|
| Severe                                     | 2 | 3 | 4 | 5 |
| Major                                      | 1 | 2 | 3 | 4 |
| Moderate                                   | 1 | 2 | 2 | 3 |
| Negligible                                 | 1 | 1 | 1 | 1 |

The values are the risk matrix example of [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html), Table H.8.

The component **star score** is `s = -0.725 x CVSS_C + 5`, clamped to `[0, 5]`, where `CVSS_C` is the combined worst-category CVSS. A clean component scores `5.00`; any vulnerability caps it at `4.75` (the 5% residual rule). The vehicle rating is the weighted average `R = Sum(s x w) / Sum(w)`.

## ▶️ Using the tool

Open `standalone.html` (or `index.html`) in a browser and use the tabs.

- **Architecture** shows how the same ECUs are reorganised across distributed, domain and zonal vehicle generations.
- **Simplified example** rates one representative vehicle, with every CVE linked to its NVD record, so the Component Stars and Vehicle Stars can be checked by hand.
- **Simulator** generates a seeded fleet from the settings above and shows how the rating is distributed. Set the fleet size, the ECUs per vehicle, the vulnerability probability, the CVSS range, the PIA probability and the seed, then run. **Reset to paper** loads the exact example from the journal.
- **Ver&Val** runs the unit and integration tests live, so the rules can be checked the moment the page loads.

Results can be exported as CSV, per vehicle, per component, or as the underlying chart data. Because runs are seeded, the same settings and seed reproduce the same fleet every time.
