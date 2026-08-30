/* =============================================================================
 * VRA, Vehicle Rating & Assessment  ·  CONFIG  (single source of truth)
 * =============================================================================
 * Every number and datum lives here; modules read from VRA.config and hard-code
 * nothing, so tuning the method means editing only this file.
 *
 * STANDARDS
 *   ISO/SAE 21434:2021, Clause 8/15 (risk assessment); Annex G §G.3 + Table G.8
 *     (CVSS feasibility E = 8.22·V·C·P·U → band); Annex H Tables H.8/H.9/H.10
 *     (risk matrix, worked examples, cross-check formula).
 *   UN ECE R155, CSMS risk-assessment backdrop (Annex 5 threat mapping: future work).
 *   ISO 26262-3, ASIL → impact input (asilToImpact).
 *   CVSS v3.1 (FIRST), AV/AC/PR/UI sub-metrics reproduce the spec exactly.
 *   GDPR Art. 33/35, context for the PIA privacy shift (piaShift).
 *   ACM CSCS'23, Algorithm 1 (component starScore).
 *
 * AUDIT
 *   • ECU roster = reference "Table 2"; each ECU keeps a `ref` to its row and a
 *     `kind` ("real" = anonymised real component, "sim" = simulated).
 *   • Not-CS-relevant rows omitted; the 18 CS-relevant components yield R = 3.65.
 *   • Finding av/ac/pr/ui sourced from NVD where enriched.
 *   • Paradigm sources: Distributed & Domain → author's journal (add citation);
 *     Zonal → SOAFEE Architecture Specification v1.0.
 * ========================================================================== */
(function () {
  "use strict";
  var VRA = (window.VRA = window.VRA || {});

  VRA.config = {

    meta: { version: "1.0", title: "Automotive Cybersecurity Rating" },

    /* ====================================================================
     * ARCHITECTURE DATA
     * ================================================================= */

    /** Functional domains present in the reference vehicle (Table 2). */
    domains: [
      { id: "ADAS",       label: "ADAS",       color: "#0b6b74" },
      { id: "Powertrain", label: "Powertrain", color: "#7a5195" },
      { id: "HMI",        label: "HMI",        color: "#bc5090" },
      { id: "Body",       label: "Body",       color: "#3f8f6e" },
      { id: "Chassis",    label: "Chassis",    color: "#2f6690" }
    ],

    /** Physical zones used by the zonal paradigm. */
    zones: ["Front-Left", "Front-Right", "Rear-Left", "Rear-Right"],

    /** External attack surfaces (drawn as infrastructure, not scored). */
    interfaces: [
      { id: "remote", label: "V2X / Cellular / Wi-Fi", kind: "remote" },
      { id: "obd",    label: "OBD-II / USB",           kind: "local"  }
    ],

    /*
     * ECUs, the reference vehicle (Table 2, CS-relevant rows only).
     * Per-ECU fields: id · name · ref (Table 2 row) · kind ("real" anonymised |
     * "sim") · domain · zone · controller/external (drawing + attack-surface
     * hints) · asil (→ impact) · pia (PII → privacy shift) · exposure (CVSS AV
     * level, metadata only, feasibility comes from the per-vuln vector) ·
     * netInteraction (Con/E-E +0, E-D +1, E-C +2 rows) · findings (each: cve,
     * cvss base, category, av/ac/pr/ui vector) · note (audit).
     * The Central Gateway / HPC is infrastructure (the core, not an assessed
     * component) and is not in this roster.
     */
    ecus: [
      /* ADAS ------------------------------------------------------------ */
      { id:"adasc", name:"Main ADAS Controller",     ref:"ADAS/Real_Comp_A", kind:"real", domain:"ADAS", zone:"Front-Right", controller:true,  external:false, asil:"D", pia:false, exposure:"Network",  netInteraction:"E-D", findings:[], note:"Anonymised real component, sensor fusion & driving-assistance hub." },
      { id:"adu",   name:"Driving Automation Unit",  ref:"ADAS/Sim_Comp_B",  kind:"sim",  domain:"ADAS", zone:"Rear-Right",  controller:false, external:true,  asil:"D", pia:false, exposure:"Adjacent", netInteraction:"E-C", findings:[], note:"Simulated, automated-driving compute, connectivity-facing." },
      { id:"cam",   name:"Front Camera",             ref:"ADAS/Sim_Comp_C",  kind:"sim",  domain:"ADAS", zone:"Front-Left",  controller:false, external:false, asil:"C", pia:false, exposure:"Adjacent", netInteraction:"E-D", findings:[], note:"Simulated, forward vision sensor." },
      { id:"radf",  name:"Front Radar",              ref:"ADAS/Sim_Comp_D",  kind:"sim",  domain:"ADAS", zone:"Front-Right", controller:false, external:false, asil:"B", pia:false, exposure:"Adjacent", netInteraction:"E-E", findings:[], note:"Simulated, forward ranging sensor." },
      { id:"radc",  name:"Corner Radar",             ref:"ADAS/Sim_Comp_E",  kind:"sim",  domain:"ADAS", zone:"Rear-Left",   controller:false, external:false, asil:"B", pia:false, exposure:"Local",    netInteraction:"E-E", findings:[], note:"Simulated, corner ranging sensor." },

      /* Powertrain ----------------------------------------------------- */
      { id:"bat",   name:"Battery Controller",       ref:"Powertrain/Real_Comp_A", kind:"real", domain:"Powertrain", zone:"Rear-Right", controller:false, external:false, asil:"B", pia:false, exposure:"Local",    netInteraction:"E-D", findings:[], note:"Anonymised real component, high-voltage battery supervision." },
      { id:"mot",   name:"Motor Control",            ref:"Powertrain/Sim_Comp_B",  kind:"sim",  domain:"Powertrain", zone:"Front-Left", controller:false, external:false, asil:"A", pia:false, exposure:"Local",    netInteraction:"E-E", findings:[], note:"Simulated, traction inverter / motor drive." },
      { id:"chg",   name:"Onboard Charger",          ref:"Powertrain/Sim_Comp_C",  kind:"sim",  domain:"Powertrain", zone:"Rear-Left",  controller:false, external:false, asil:"A", pia:false, exposure:"Physical", netInteraction:"Con", findings:[], note:"Simulated, onboard charging unit." },

      /* HMI ------------------------------------------------------------ */
      { id:"hu",    name:"Infotainment Head Unit",   ref:"HMI/Sim_Comp_A", kind:"sim", domain:"HMI", zone:"Front-Right", controller:true,  external:true,  asil:"QM", pia:true, exposure:"Network",  netInteraction:"E-C", findings:[{cve:"CVE-2018-20342",cvss:6.8,category:"Software",av:"P",ac:"L",pr:"N",ui:"N"},{cve:"CVE-2017-5579",cvss:6.5,category:"Networks",av:"L",ac:"L",pr:"L",ui:"N"}], note:"Simulated, infotainment & central display, connectivity-facing." },
      { id:"cdu",   name:"Central Infotainment Head Unit",ref:"HMI/Real_Comp_B", kind:"real", domain:"HMI", zone:"Rear-Right",  controller:false, external:true,  asil:"QM", pia:true, exposure:"Physical", netInteraction:"E-C", findings:[
          /* Anonymised REAL head unit, publicly disclosed findings (see the CVE
           * links). FRAMEWORK TREATMENT (ISO/SAE 21434 + R155 CSMS):
           * findings ≥ 7.0 are reported-and-mitigated by the supplier and excluded
           * (matches the ≥7 critical branch), CVE-2023-34399 (9.8), 34402 (7.7),
           * 34397/34398/34400 (7.5); sub-7 findings are accepted residual risk.
           * Categories verified NVD/CWE. All physical/USB (AV:P → Very Low
           * feasibility): high severity yet low feasibility. */
          {cve:"CVE-2024-37600",cvss:6.8,category:"Software",av:"P",ac:"L",pr:"N",ui:"N"},
          {cve:"CVE-2024-37602",cvss:4.6,category:"Networks",av:"P",ac:"L",pr:"N",ui:"N"},
          {cve:"CVE-2024-37601",cvss:4.6,category:"Software",av:"P",ac:"L",pr:"N",ui:"N"}
        ], note:"Anonymised real component, infotainment head unit (publicly disclosed CVEs; follow the CVE links to the NVD). Findings ≥7 (incl. CVE-2023-34399 at 9.8) are reported-and-mitigated by the supplier and excluded; sub-7 findings carried as accepted residual risk (ISO/SAE 21434)." },
      { id:"ic",    name:"Instrument Cluster",       ref:"HMI/Sim_Comp_C", kind:"sim", domain:"HMI", zone:"Front-Left",  controller:false, external:false, asil:"A",  pia:true, exposure:"Adjacent", netInteraction:"E-E", findings:[
          /* CASE 2, two DISTINCT finding categories, both < 5.3
           * → X = 0.6·C₀ + 0.4·C₁. Uses the two INDUSTRY sample CVEs (A + B):
           *   CVE-2017-14937 broken crypto algorithm (CWE-327) → Cryptography 4.7
           *   CVE-2018-17977 memory-safety (Linux)             → Software     4.4 */
          {cve:"CVE-2017-14937",cvss:4.7,category:"Diagnostics",av:"A",ac:"L",pr:"N",ui:"N"},
          {cve:"CVE-2018-17977",cvss:4.4,category:"Software",av:"L",ac:"L",pr:"H",ui:"N"}
        ], note:"Simulated, driver information display; two sub-5.3 findings in distinct categories illustrate starScore Case 2." },

      /* Body ----------------------------------------------------------- */
      { id:"lgt",   name:"Interior Lighting",        ref:"Body/Sim_Comp_A", kind:"sim", domain:"Body", zone:"Rear-Left",  controller:false, external:false, asil:"QM", pia:false, exposure:"Physical", netInteraction:"Con", findings:[], note:"Simulated, interior lighting module." },
      { id:"door",  name:"Door Control Module",      ref:"Body/Sim_Comp_B", kind:"sim", domain:"Body", zone:"Front-Left", controller:false, external:false, asil:"QM", pia:false, exposure:"Local",    netInteraction:"E-E", findings:[{cve:"CVE-2018-17977",cvss:4.4,category:"Software",av:"L",ac:"L",pr:"H",ui:"N"}], note:"Simulated, locks, windows, mirrors." },
      { id:"bcm",   name:"Body Control Module",      ref:"Body/Sim_Comp_C", kind:"sim", domain:"Body", zone:"Rear-Left",  controller:true,  external:false, asil:"A",  pia:false, exposure:"Local",    netInteraction:"E-D", findings:[
          /* CASE 3, three DISTINCT finding categories, all < 5.3
           * → X = 0.6·C₀ + 0.3·C₁ + 0.1·C₂. Three real sample CVEs, TWO industry
           * + ONE from a public disclosure report, all verified via NVD/CWE:
           *   CVE-2017-14937 broken crypto algorithm (CWE-327)  [industry] → Cryptography 4.7
           *   CVE-2023-34404 command injection, networking svc  [MB report]→ Networks     4.9
           *   CVE-2018-17977 memory-safety (Linux)              [industry] → Software     4.4 */
          {cve:"CVE-2017-14937",cvss:4.7,category:"Diagnostics",av:"A",ac:"L",pr:"N",ui:"N"},
          {cve:"CVE-2023-34404",cvss:4.9,category:"Networks",av:"A",ac:"L",pr:"N",ui:"N"},
          {cve:"CVE-2018-17977",cvss:4.4,category:"Software",av:"L",ac:"L",pr:"H",ui:"N"}
        ], note:"Simulated, body domain hub; three sub-5.3 findings in distinct categories (two industry + one from the MB report) illustrate starScore Case 3." },
      { id:"seat",  name:"Seat Control Module",      ref:"Body/Sim_Comp_D", kind:"sim", domain:"Body", zone:"Rear-Right", controller:false, external:false, asil:"QM", pia:false, exposure:"Physical", netInteraction:"Con", findings:[], note:"Simulated, powered seat module." },

      /* Chassis -------------------------------------------------------- */
      { id:"susp",  name:"Suspension Control",       ref:"Chassis/Sim_Comp_A", kind:"sim", domain:"Chassis", zone:"Rear-Right", controller:false, external:false, asil:"A",  pia:false, exposure:"Local",    netInteraction:"E-E", findings:[], note:"Simulated, active suspension control." },
      { id:"tpms",  name:"Tire Pressure Monitor",    ref:"Chassis/Sim_Comp_B", kind:"sim", domain:"Chassis", zone:"Rear-Left",  controller:false, external:false, asil:"QM", pia:false, exposure:"Physical", netInteraction:"Con", findings:[], note:"Simulated, TPMS." },
      { id:"park",  name:"Parking Assist Sensor",    ref:"Chassis/Sim_Comp_C", kind:"sim", domain:"Chassis", zone:"Front-Right",controller:false, external:false, asil:"QM", pia:false, exposure:"Physical", netInteraction:"Con", findings:[], note:"Simulated, parking assistance sensor." }
    ],

    /*
     * Architecture paradigms.
     * Each carries a caption, a source reference, and (zonal) the SOAFEE
     * principles.  Distributed/Domain captions summarise the author's journal
     * narrative, replace `reference.cite` with the final citation.
     */
    paradigms: {
      distributed: {
        label: "Distributed E/E", era: "Yesterday", grouping: "domain", core: "bus",
        caption: "Every ECU shares a single bus (typically CAN) with no internal segmentation, and the only way in is a physical connector, at best the OBD port. There is no remote or V2X surface yet, but the network is flat, so any node reached physically has line-of-sight to the whole vehicle.",
        reference: { cite: "Author's journal, E/E architecture evolution (replace with final citation)", url: "" }
      },
      domain: {
        label: "Domain-centralised E/E", era: "Today", grouping: "domain", core: "gateway",
        caption: "Functions consolidate behind per-domain controllers that meet at a central gateway. The gateway mediates cross-domain traffic and is the primary security boundary between domains, the dominant production topology today.",
        reference: { cite: "Author's journal, E/E architecture evolution (replace with final citation)", url: "" }
      },
      zonal: {
        label: "Zonal E/E (SDV)", era: "Tomorrow", grouping: "zone", core: "hpc",
        caption: "ECUs wire to the nearest zonal controller by location; zones meet at a High-Performance Computer over automotive Ethernet. Under SOAFEE, vehicle functions become cloud-native workloads on the HPC, where non-safety (QM) and safety-critical (ASIL) services share one platform. Security now hinges on that shared architecture: a remote compromise lands in the non-safety partition, and the Freedom From Interference boundary is the trust boundary that must stop it reaching safety functions, enforced by least-privilege orchestration and application attestation.",
        reference: { cite: "SOAFEE Architecture Specification v1.0", url: "https://architecture.docs.soafee.io/en/latest/index.html" },
        principles: [
          "Software-defined vehicle: HW/SW separation via a SOAFEE-compliant abstraction layer",
          "Mixed-criticality integration: non-safety (QM) and safety-critical (ASIL) workloads on one HPC",
          "Freedom From Interference: the FFI boundary is the trust boundary between safety levels",
          "Least-privilege orchestration: containers and attestation gates enforce isolation"
        ]
      }
    },

    /** Consolidated source list (shown in the Details tab, for audit). */
    references: [
      { tag: "Distributed / Domain", cite: "Author's journal, E/E architecture evolution", note: "replace with final citation", url: "" },
      { tag: "Zonal (SDV)",          cite: "SOAFEE Architecture Specification v1.0", url: "https://architecture.docs.soafee.io/en/latest/index.html" },
      { tag: "Reference vehicle",    cite: "Table 2, Component Vulnerability Assessment; each ECU's `ref` traces to its row (R = 3.65)", url: "" }
    ],

    /* ====================================================================
     * SCORING CONSTANTS
     * ================================================================= */
    scoring: {

      /* ═══════════════════════════════════════════════════════════════
       *  COMPONENT LEVEL, starScore s  (per ECU · ACM CSCS'23 Algorithm 1)
       *  Pipeline: keep the worst CVSS per category → sort desc → keep the
       *  3 worst → C (size n). Branches:
       *    (A) all C < 5.3          → weighted cases 1/2/3 (caseWeights)
       *    (B) some C in [5.3, 7)   → worst-case, X = C₀ (single vuln)
       *    (C) any C ≥ 7            → critical-risk error (excluded)
       *  Then s = slope·X + intercept, clamped [min,max]; no finding → clean.
       * ═══════════════════════════════════════════════════════════════ */
      starScore: {
        intercept: 5,
        slope: -0.725,               // s = −0.725·X + 5
        min: 0, max: 5, clean: 5,    // no finding → full 5.00 (means zero vulnerabilities)
        residualFraction: 0.05,      // once ANY vulnerability exists we cannot certify
                                     // more than 95% secure, so a vulnerable component
                                     // is capped at max·(1−0.05) = 4.75. A 5.00 means
                                     // no vulnerabilities, nothing else.
        maxCategories: 3,            // only the 3 worst categories count
        lowThreshold: 5.3,           // < 5.3 → weighted cases 1/2/3
        highThreshold: 7.0,          // ≥ 7.0 → critical-risk error
        criticalError: "critical security risk detected",
        caseWeights: { "1": [1.00], "2": [0.60, 0.40], "3": [0.60, 0.30, 0.10] }
      },
      // Finding categories (worst-per-category grouping). Illustrative taxonomy.
      findingCategories: ["Networks", "Software", "Cryptography", "Diagnostics", "Physical", "Access-Control"],

      /* ═══════════════════════════════════════════════════════════════
       *  VEHICLE LEVEL, weight w  (ISO/SAE 21434 Annex H, Table H.8)
       *  w = H.8[impact][feasibility] ∈ [1,5]. Impact = H.8 row (from ASIL),
       *  feasibility = H.8 column (from CVSS exploitability + interaction).
       * ═══════════════════════════════════════════════════════════════ */

      //, Impact axis (H.8 row): ASIL → impact, then +PIA promotion ,
      impactLevels: ["Negligible", "Moderate", "Major", "Severe"],
      asilToImpact: { QM: "Negligible", A: "Moderate", B: "Major", C: "Severe", D: "Severe" },
      piaShift: 1,                   // PIA-confirmed PII → promote impact +1 (capped)

      //, Feasibility axis (H.8 column): CVSS exploitability E → G.8 band ,
      // Annex G.3: E = k·AV·AC·PR·UI (CVSS v3.1 sub-metrics, calculator-exact).
      // PR = scope Unchanged for feasibility; PRchanged only for the full base score.
      cvss: {
        k: 8.22,
        AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
        AC: { L: 0.77, H: 0.44 },
        PR: { N: 0.85, L: 0.62, H: 0.27 },
        PRchanged: { N: 0.85, L: 0.68, H: 0.50 },
        UI: { N: 0.85, R: 0.62 }
      },
      // Annex G, Table G.8: E → feasibility band (lower-bound inclusive).
      // Very Low 0.12–1.05 · Low 1.06–1.99 · Medium 2.00–2.95 · High 2.96–3.89.
      feasibilityBands: [
        { label: "Very Low", minE: 0.12, col: 0 },
        { label: "Low",      minE: 1.06, col: 1 },
        { label: "Medium",   minE: 2.00, col: 2 },
        { label: "High",     minE: 2.96, col: 3 }
      ],
      feasibilityLevels: ["Very Low", "Low", "Medium", "High"],
      cleanBaseFeasibility: "Very Low",   // no finding → lowest base band (shift still applies)
      // Interaction shift: how far a compromise propagates (from the comms matrix).
      // Con/E-E +0 (same domain), E-D +1 (cross-domain), E-C +2 (connectivity).
      networkInteractionShift: { "Con": 0, "E-E": 0, "E-D": 1, "E-C": 2 },

      //, Risk matrix: H.8 weight + H.10 cross-check ,
      // h8[impact][feasibilityCol] → w ∈ [1,5]. Rows: Negligible…Severe; cols: VeryLow…High.
      h8: {
        Negligible: [1, 1, 1, 1],
        Moderate:   [1, 2, 2, 3],
        Major:      [1, 2, 3, 4],
        Severe:     [2, 3, 4, 5]
      },
      weightMax: 5,
      // Table H.10 alt. formula R = const + impact×feasibility, independent H.8 cross-check only.
      h10: {
        impactValue:      { Negligible: 0, Moderate: 1, Major: 1.5, Severe: 2 },
        feasibilityValue: { "Very Low": 0, "Low": 1, "Medium": 1.5, "High": 2 },
        riskConstant: 1
      },

      /* ═══ SHARED / REFERENCE (labelling & informational) ═══ */
      // CVSS v3.1 §5 severity scale (base score → label). Generation caps at 6.9.
      cvssSeverity: [
        { label: "None",     min: 0.0, max: 0.0,  color: "#5b6670" },
        { label: "Low",      min: 0.1, max: 3.9,  color: "#1a9850" },
        { label: "Medium",   min: 4.0, max: 6.9,  color: "#fee08b" },
        { label: "High",     min: 7.0, max: 8.9,  color: "#f46d43" },
        { label: "Critical", min: 9.0, max: 10.0, color: "#a50026" }
      ]
    },

    /* ====================================================================
     * SIMULATION DEFAULTS
     * --------------------------------------------------------------------
     * Fleet generator inputs. Non-obvious ones:
     *   ecuCount 0–100 spans distributed (many small ECUs) → domain → zonal/HPC
     *     (fewer, larger); 0 is the clean-fleet proof (every vehicle 5★).
     *   vulnProbMode: "manual" (the number) · "features" (derived from selected
     *     security features) · "featuresRandom" (per-vehicle seeded feature set).
     *   vulnRange: v3.1 base scores are discrete (achievable 1.6–9.8); the
     *     generator enumerates the EXACT achievable set inside [min,max] and
     *     reports an empty range rather than mis-generating. Max ≤ 6.9 keeps the
     *     starScore off the critical branch.
     *   domain / asilByDomain / netInteractionByDomain: shares over the domains
     *     / ASIL levels / interaction levels; each row sums to 1.
     * Every generated finding is a real scope-U CVSS v3.1 vector: its base score
     * (starScore input) and exploitability E (feasibility input) stay consistent.
     * ================================================================= */
    simulation: {
      seed: 21434,
      vehicles: 10000,
      ecuCount: 25,
      vulnProbability: 0.24,
      vulnProbMode: "manual",
      vulnRange: [0.1, 6.9],
      findingsPerEcu: [1, 3],
      piaProbability: 0.15,

      /* Domain mix (order = config.domains). Sums to 1. */
      domainProbability: { ADAS: 0.20, Powertrain: 0.20, HMI: 0.20, Body: 0.20, Chassis: 0.20 },

      /* ASIL distribution PER domain (order QM, A, B, C, D). Each row sums to 1.
       * Paper "typical vehicle" configuration: the same QM 10 / A 20 / B 25 /
       * C 25 / D 20 (%) mix is applied to every domain. */
      asilByDomain: {
        ADAS:       [0.10, 0.20, 0.25, 0.25, 0.20],
        Powertrain: [0.10, 0.20, 0.25, 0.25, 0.20],
        HMI:        [0.10, 0.20, 0.25, 0.25, 0.20],
        Body:       [0.10, 0.20, 0.25, 0.25, 0.20],
        Chassis:    [0.10, 0.20, 0.25, 0.25, 0.20]
      },

      /* Network-interaction mix PER domain (order Con, E-E, E-D, E-C).
       * Paper "typical vehicle" configuration: the same Contained 25 / E-E 35 /
       * E-D 25 / E-C 15 (%) mix is applied to every domain. In a real assessment
       * these come from the vehicle communication matrix. */
      netInteractionByDomain: {
        ADAS:       [0.25, 0.35, 0.25, 0.15],
        Powertrain: [0.25, 0.35, 0.25, 0.15],
        HMI:        [0.25, 0.35, 0.25, 0.15],
        Body:       [0.25, 0.35, 0.25, 0.15],
        Chassis:    [0.25, 0.35, 0.25, 0.15]
      },

      /* Security-feature catalogue → vulnerability probability.
       * Ported verbatim from the previous simulator. Probability starts at
       * base (completely unsecured ECU) and each enabled feature subtracts
       * its weight; groups are mutually exclusive; the floor reflects that
       * no system is fully secure.
       * The WEIGHTS ARE ILLUSTRATIVE ASSUMPTIONS (as in the original) and
       * shall be calibrated with industry before real-world use, they set
       * the simulation input probability only and touch no standard formula. */
      securityFeatures: {
        base: 1.0,
        floor: 0.05,
        catalogue: [
          { id: "secure-boot",  label: "Secure Boot",                      weight: 0.06 },
          { id: "secure-flash", label: "Secure Flashing",                  weight: 0.06 },
          { id: "secure-ota",   label: "Secure Updates (OTA)",             weight: 0.05 },
          { id: "hsm", label: "HSM (EVITA)", options: [
            { id: "hsm-full",   label: "HSM EVITA, Full",                 weight: 0.25 },
            { id: "hsm-medium", label: "HSM EVITA, Medium (SHE)",         weight: 0.15 }
          ]},
          { id: "secoc",        label: "Secure Communication (SecOC)",     weight: 0.10 },
          { id: "jtag", label: "JTAG Lock", options: [
            { id: "jtag-single", label: "JTAG Lock, Single Password",     weight: 0.06 },
            { id: "jtag-indiv",  label: "JTAG Lock, Password Per ECU",    weight: 0.10 }
          ]},
          { id: "diag", label: "Secure Diagnostics", options: [
            { id: "diag-0x27",  label: "UDS 0x27 SecurityAccess",          weight: 0.06 },
            { id: "diag-0x29",  label: "UDS 0x29 Authentication",          weight: 0.12 }
          ]},
          { id: "ids",          label: "IDS, AI Intrusion Detection",     weight: 0.02 },
          { id: "ips",          label: "IPS, AI Intrusion Prevention",    weight: 0.06 },
          { id: "firewall", label: "Firewall", options: [
            { id: "fw-white",   label: "Firewall, Whitelist-Based",       weight: 0.14 },
            { id: "fw-black",   label: "Firewall, Blacklist-Based",       weight: 0.10 }
          ]},
          { id: "fw-ai",        label: "AI Firewall Adaptation",           weight: 0.07 },
          { id: "rt-adapt",     label: "Real-time Attack Adaptation",      weight: 0.09 },
          { id: "fleet-learn",  label: "AI Learning & Fleet-wide Update",  weight: 0.07 }
        ]
      },

      /* CVSS v3.1 impact-metric numerical values (None/Low/High). */
      cvssImpact: { N: 0, L: 0.22, H: 0.56 },

      /* Detailed per-component records are kept up to this many components
       * (vehicles × ecuCount) so the per-component CSV stays exportable
       * without exhausting memory on very large fleets. */
      maxComponentRecords: 300000,

      /* Histogram resolution for the rating distribution chart. */
      bins: 20
    }
  };

  /* ---- MODEL FACADE: thin, pure lookups over the data above -------- */
  VRA.model = {
    domain: function (id) { var d = VRA.config.domains; for (var i = 0; i < d.length; i++) if (d[i].id === id) return d[i]; return null; },
    color:  function (id) { var d = this.domain(id); return d ? d.color : "#888"; },
    ecu:    function (id) { var e = VRA.config.ecus; for (var i = 0; i < e.length; i++) if (e[i].id === id) return e[i]; return null; }
  };
})();
