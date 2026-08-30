/* =============================================================================
 * VRA — Vehicle Rating & Assessment  ·  Module: SIMULATION
 * =============================================================================
 * SCOPE
 *   Generate synthetic vehicle fleets and run each vehicle through the SAME
 *   component-starScore + Table H.8 weight + Σ(s·w)/Σ(w) pipeline as the live
 *   reference vehicle (via VRA.vehicle.rateSet — no logic is duplicated here).
 *   Reports the rating distribution, both Table H.8 axes, the CVSS picture,
 *   and exports the generated data per vehicle AND per component.
 *
 * STANDARDS COMPLIANCE
 *   ISO/SAE 21434:2021    exercises the full risk assessment (Annexes G + H)
 *                          across a population.
 *   UN ECE R155           §7.2.2.2 — continuous risk assessment for CSMS type
 *                          approval at fleet scale.
 *   CVSS v3.1 (FIRST)     every generated vulnerability is a real v3.1 vector
 *                          (scope-unchanged), drawn from the ENUMERATED set of
 *                          achievable base scores inside the configured range;
 *                          base score (starScore input) and exploitability E
 *                          (feasibility input) come from the official formulas
 *                          and are always mutually consistent.
 *   ISO 26262-3           ASIL drives the impact class.
 *
 * BOUNDARY CORRECTNESS (fixes the observed mis-generation)
 *   CVSS v3.1 base scores are DISCRETE: with C/I/A ∈ {N,L,H} and scope U the
 *   achievable positive scores span exactly 1.6 … 9.8. The old rejection
 *   sampler could return an out-of-range (even ≥ 7) vector when the range was
 *   narrow or unachievable. The generator now ENUMERATES all 1296 scope-U
 *   vectors once per run and keeps those whose base score lies inside [min,max];
 *   an empty pool is REPORTED (result.warning) instead of being silently
 *   mis-generated, and min > max inputs are normalised by swapping.
 *
 * FEASIBILITY-FAITHFUL DRAW (E-approach)
 *   Feasibility depends only on exploitability E = 8.22·V·C·P·U (AV/AC/PR/UI),
 *   while the base score also folds in impact (C/I/A). Sampling uniformly over
 *   full vectors skews E low — high-E vectors are rare once the base is capped —
 *   so feasibility would never leave Very Low/Low on its own. The pool is
 *   therefore GROUPED by exploitability vector: each draw picks a group first
 *   (so E is representative across all Table G.8 bands), then an impact within
 *   it (so the base stays in the severity range). Both axes remain real v3.1
 *   metrics, so 02/03's feasibility logic is reproduced exactly and every E
 *   lands in the ISO range [0.12, 3.89].
 *
 * PORTED FROM THE PREVIOUS SIMULATOR (Python)
 *   • Security-feature catalogue → vulnerability probability (base 1.0,
 *     floor 0.05, mutually-exclusive groups) — manual selection or seeded
 *     per-vehicle random selection ("auto" mode, now reproducible).
 *   • 1–3 vulnerabilities per affected ECU (randint(1,3)).
 *   • Per-domain interaction mix (INTERACTION_RISK_MAP intent).
 *   • min AND max vulnerability score controls; runs = vehicles; raw export.
 *
 * REPLICABILITY
 *   One seeded PRNG (mulberry32) drives ALL randomness — including random
 *   feature selection — so the same seed + config reproduce a byte-identical
 *   fleet. The seed is written into every CSV export.
 *
 * PUBLIC API
 *   VRA.simulation.run(overrides?)        → full result object
 *   VRA.simulation.toCSV(result)          → per-vehicle CSV
 *   VRA.simulation.toComponentCSV(result) → per-component CSV (raw data)
 *   VRA.simulation.vulnProbFromFeatures(ids) / buildVulnPool(lo, hi)
 *   VRA.simulation.verify() / init()
 * ========================================================================== */
(function () {
  "use strict";
  var VRA = (window.VRA = window.VRA || {});
  function CFG() { return VRA.config; }
  function SIM() { return VRA.config.simulation; }
  function SC()  { return VRA.config.scoring; }

  /* ===========================================================================
   * 1. SEEDED RNG  (mulberry32 — small, deterministic, good distribution)
   * =========================================================================*/
  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  /** Pick an index from a weight array (need not be normalised). */
  function pickIndex(rng, weights) {
    var sum = 0, i;
    for (i = 0; i < weights.length; i++) sum += weights[i];
    var r = rng() * sum;
    for (i = 0; i < weights.length; i++) { r -= weights[i]; if (r < 0) return i; }
    return weights.length - 1;
  }

  /* ===========================================================================
   * 2. CVSS v3.1 BASE SCORE  — calculator-exact
   * ------------------------------------------------------------------------
   * FIRST CVSS v3.1 Specification §7.1
   * (https://www.first.org/cvss/v3.1/specification-document, user guide
   *  https://www.first.org/cvss/v3.1/user-guide).
   * ISS      = 1 − (1−C)(1−I)(1−A)                     C/I/A ∈ {N:0, L:0.22, H:0.56}
   * Impact   = 6.42·ISS                                (scope Unchanged)
   *          = 7.52·(ISS−0.029) − 3.25·(ISS−0.02)^15   (scope Changed)
   * Exploit  = 8.22·AV·AC·PR·UI    (PR scope-adjusted when Changed)
   * Base     = 0                    if Impact ≤ 0
   *          = Roundup(min(Impact+Exploit, 10))        (scope Unchanged)
   *          = Roundup(min(1.08·(Impact+Exploit), 10)) (scope Changed)
   * Roundup  = the exact v3.1 one-decimal rounding (Appendix A).
   * Verified against the official calculator (V&V): 6.8, 5.9, 4.4 (U); 6.5 (C); 9.8 (max).
   * =========================================================================*/
  function roundup(x) {
    var i = Math.round(x * 100000);
    return (i % 10000 === 0) ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
  }
  function cvssBase(v) {
    var c = SC().cvss, im = SIM().cvssImpact, changed = (v.scope === "C");
    var iss = 1 - (1 - im[v.c]) * (1 - im[v.i]) * (1 - im[v.a]);
    var impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    if (impact <= 0) return 0;
    var pr = (changed ? c.PRchanged : c.PR)[v.pr];
    var expl = c.k * c.AV[v.av] * c.AC[v.ac] * pr * c.UI[v.ui];
    return roundup(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
  }
  /** CVSS v3.1 qualitative severity label for a base score (§5). */
  function cvssSeverity(score) {
    var levels = SC().cvssSeverity;
    for (var i = 0; i < levels.length; i++) if (score >= levels[i].min && score <= levels[i].max) return levels[i];
    return levels[0];
  }

  /* ===========================================================================
   * 4. VULNERABILITY POOL  (exact achievable-score enumeration — boundary fix)
   * =========================================================================*/
  var AV_K = ["N", "A", "L", "P"], AC_K = ["L", "H"], PR_K = ["N", "L", "H"],
      UI_K = ["N", "R"], IMP_K = ["N", "L", "H"];

  /**
   * Enumerate every scope-Unchanged CVSS v3.1 vector (4·2·3·2·27 = 1296) and
   * keep those whose base score is positive and inside [lo, hi]. Sampling from
   * this pool honours the configured boundaries EXACTLY — no rejection, no
   * silent out-of-range vectors. An empty pool means no v3.1 base score is
   * achievable in the range (achievable positive scores span 1.6–9.8).
   */
  function buildVulnPool(lo, hi) {
    var pool = [];
    AV_K.forEach(function (av) { AC_K.forEach(function (ac) { PR_K.forEach(function (pr) { UI_K.forEach(function (ui) {
      IMP_K.forEach(function (c) { IMP_K.forEach(function (i) { IMP_K.forEach(function (a) {
        var v = { av: av, ac: ac, pr: pr, ui: ui, c: c, i: i, a: a };
        var b = cvssBase(v);
        if (b > 0 && b >= lo && b <= hi) { v.base = b; pool.push(v); }
      }); }); });
    }); }); }); });
    return pool;
  }

  /* Group the pool by EXPLOITABILITY vector (AV/AC/PR/UI). Feasibility E depends
   * only on these four metrics (E = 8.22·V·C·P·U), while the base score also
   * folds in impact (C/I/A). Drawing uniformly over full vectors skews E low
   * (high-E vectors are rare once the base is capped). Grouping lets us draw the
   * exploitability vector first — so E is representative across all Table G.8
   * bands — then draw an impact within that group so the base stays in range.
   * This is strictly CVSS-valid: both axes are real v3.1 metrics. */
  function groupByExploit(pool) {
    var map = {}, order = [];
    pool.forEach(function (v) {
      var key = v.av + v.ac + v.pr + v.ui;
      if (!map[key]) { map[key] = { av: v.av, ac: v.ac, pr: v.pr, ui: v.ui, E: VRA.vehicle.exploitability(v), entries: [] }; order.push(key); }
      map[key].entries.push(v);
    });
    return order.map(function (k) { return map[k]; });
  }

  /* Draw one vulnerability: pick an exploitability group (→ E spans G.8 bands),
   * then an impact entry within it (→ base score in the requested range). */
  function drawVuln(rng, groups, category) {
    var g = groups[(rng() * groups.length) | 0];
    var v = g.entries[(rng() * g.entries.length) | 0];
    return { cve: "SIM", cvss: v.base, category: category, av: v.av, ac: v.ac, pr: v.pr, ui: v.ui };
  }

  /**
   * Pick k DISTINCT finding categories (seeded partial Fisher–Yates shuffle).
   * Distinct categories are what let a below-5.3 component reach the weighted
   * Case 2 / Case 3 branches of the star score — with categories drawn with
   * replacement, repeated categories collapse (anti-dilution) back to Case 1.
   */
  function pickCategories(rng, k) {
    var cats = SC().findingCategories.slice(), n = cats.length, out = [];
    k = Math.min(k, n);
    for (var i = 0; i < k; i++) {
      var j = i + ((rng() * (n - i)) | 0), t = cats[i];
      cats[i] = cats[j]; cats[j] = t;
      out.push(cats[i]);
    }
    return out;
  }

  /* ===========================================================================
   * 5. SECURITY FEATURES → VULNERABILITY PROBABILITY  (ported catalogue)
   * ------------------------------------------------------------------------
   * base 1.0 (unsecured ECU) − Σ(enabled feature weights), floored at 0.05
   * (no system is fully secure). Groups are mutually exclusive: only the
   * first selected option of a group counts. Weights are illustrative
   * assumptions (as in the original) pending industry calibration.
   * =========================================================================*/
  function vulnProbFromFeatures(selectedIds) {
    var sf = SIM().securityFeatures, p = sf.base, ids = selectedIds || [];
    sf.catalogue.forEach(function (f) {
      if (f.options) {
        for (var i = 0; i < f.options.length; i++) {           // mutually exclusive
          if (ids.indexOf(f.options[i].id) !== -1) { p -= f.options[i].weight; break; }
        }
      } else if (ids.indexOf(f.id) !== -1) {
        p -= f.weight;
      }
    });
    return Math.max(sf.floor, Math.round(p * 100) / 100);
  }

  /** Seeded random feature selection (the old "auto" mode, now reproducible). */
  function randomFeatureSelection(rng) {
    var sf = SIM().securityFeatures, ids = [];
    sf.catalogue.forEach(function (f) {
      if (f.options) {
        var k = (rng() * (f.options.length + 1)) | 0;          // None + options, equal chance
        if (k < f.options.length) ids.push(f.options[k].id);
      } else if (rng() < 0.5) {
        ids.push(f.id);
      }
    });
    return ids;
  }

  /* ===========================================================================
   * 6. SYNTHETIC GENERATION  (component → vehicle)
   * =========================================================================*/
  var ASIL_K = ["QM", "A", "B", "C", "D"], NET_K = ["Con", "E-E", "E-D", "E-C"];

  /* Case coverage (Algorithm 1 branches), in display order.
   *   Clean       no confirmed finding                → starScore 5
   *   Case 1      1 category,  all < 5.3              → X = 1.0·C₀
   *   Case 2      2 categories, all < 5.3             → X = 0.6·C₀ + 0.4·C₁
   *   Case 3      3 categories, all < 5.3             → X = 0.6·C₀ + 0.3·C₁ + 0.1·C₂
   *   Worst-case  any category ≥ 5.3 (and < 7)        → X = C₀ only (single vuln)
   *   Critical    any category ≥ 7                    → escalated, excluded from mean */
  var CASE_ORDER = ["Clean", "Case 1", "Case 2", "Case 3", "Worst-case", "Critical"];
  function caseLabelOf(st) {
    if (st.critical) return "Critical";
    if (st.case === 0) return "Clean";
    if (st.case === 1) return "Case 1";
    if (st.case === 2) return "Case 2";
    if (st.case === 3) return "Case 3";
    return "Worst-case";
  }

  /** Generate one synthetic component (all inputs the rating pipeline needs). */
  function genEcu(rng, p, groups, vulnProb, idx) {
    var domains = CFG().domains.map(function (d) { return d.id; });
    var domain = domains[pickIndex(rng, domains.map(function (d) { return p.domainProbability[d] || 0; }))];
    var asil = ASIL_K[pickIndex(rng, p.asilByDomain[domain] || [1, 0, 0, 0, 0])];
    var net = NET_K[pickIndex(rng, p.netInteractionByDomain[domain] || [1, 0, 0, 0])];
    var pia = rng() < p.piaProbability;

    var findings = [];
    if (groups.length && rng() < vulnProb) {
      var lo = p.findingsPerEcu[0], hi = p.findingsPerEcu[1];
      var k = lo + ((rng() * (hi - lo + 1)) | 0); if (k > hi) k = hi;
      var picks = pickCategories(rng, k);
      for (var j = 0; j < k; j++) findings.push(drawVuln(rng, groups, picks[j]));
    }
    return {
      id: "e" + idx, name: domain + "-ECU-" + idx, domain: domain,
      asil: asil, pia: pia, netInteraction: net, findings: findings
    };
  }

  /* ===========================================================================
   * 7. FLEET RUN  (reuses VRA.vehicle.rateSet — identical to the live pipeline)
   * =========================================================================*/
  function merge(overrides) {
    var base = SIM(), p = {}, k, has = Object.prototype.hasOwnProperty;
    for (k in base) if (has.call(base, k)) p[k] = base[k];
    if (overrides) for (k in overrides) if (has.call(overrides, k)) p[k] = overrides[k];
    /* Boundary normalisation: swap inverted range, clamp to [0, 6.9]. */
    var lo = Math.min(p.vulnRange[0], p.vulnRange[1]);
    var hi = Math.max(p.vulnRange[0], p.vulnRange[1]);
    p.vulnRange = [Math.max(0, lo), Math.min(6.9, hi)];
    return p;
  }

  /**
   * Generate and rate a fleet.
   * @param {object} [overrides] partial config overriding the defaults
   * @returns result: { params, ratings, vehicles, components, stats, histogram,
   *                    weightByImpact, weightByFeasibility, cvss, criticalRate,
   *                    vulnProbUsed, warning }
   */
  /* Run the same pipeline at growing ECU counts and record the mean rating, so
   * the chart can show the rules hold from a small car to a 100-ECU one. Uses a
   * fixed seed and a modest fleet per point so it stays fast and reproducible. */
  function scalabilitySweep(baseParams) {
    var counts = [1, 5, 10, 25, 50, 75, 100];
    return counts.map(function (c) {
      var r = run({ ecuCount: c, vehicles: 400, seed: (baseParams && baseParams.seed) || 21434,
        vulnProbability: (baseParams && baseParams.vulnProbability != null) ? baseParams.vulnProbability : 0.24,
        vulnProbMode: "manual", vulnRange: (baseParams && baseParams.vulnRange) || [0.1, 6.9] });
      return { ecuCount: c, meanR: r.stats.mean };
    });
  }

  function run(overrides) {
    var p = merge(overrides);
    var rng = mulberry32(p.seed);
    var impactLevels = SC().impactLevels, feasLevels = SC().feasibilityLevels;

    /* Exact achievable-vector pool for the configured range (boundary fix),
     * grouped by exploitability vector so feasibility E spans all G.8 bands. */
    var pool = buildVulnPool(p.vulnRange[0], p.vulnRange[1]);
    var groups = groupByExploit(pool);
    var warning = pool.length ? null :
      "No CVSS v3.1 base score is achievable in [" + p.vulnRange[0].toFixed(1) + ", " + p.vulnRange[1].toFixed(1) +
      "] — achievable positive scores span 1.6\u20139.8. The fleet was generated without vulnerabilities.";

    /* Vulnerability probability follows the same 5% rule as the score: it is
     * either 0 (a deliberately clean fleet, every component 5.00) or at least 5%.
     * Anything between 0 and 5% is snapped up to 5%, because we can never claim
     * less than 5% uncertainty once a vulnerability is possible. So 1%, 2%, 3%
     * and 4% are not valid inputs. */
    var vulnFloor = SC().starScore.residualFraction;
    function probRule(pr) { return pr <= 0 ? 0 : Math.max(pr, vulnFloor); }
    var fixedProb = probRule(p.vulnProbability);
    if (p.vulnProbMode === "features") fixedProb = probRule(vulnProbFromFeatures(p.securitySelection));

    var keepComponents = (p.vehicles * Math.max(1, p.ecuCount)) <= p.maxComponentRecords;
    var ratings = [], vehicles = [], components = keepComponents ? [] : null;

    var wSum = {}, wCount = {}, wSumF = {}, wCountF = {};
    var wHist = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };   // Table H.8 weight distribution
    var h8Count = {};                                // Table H.8 cell counts: impact × feasibility
    impactLevels.forEach(function (L) { wSum[L] = 0; wCount[L] = 0; h8Count[L] = {}; feasLevels.forEach(function (F) { h8Count[L][F] = 0; }); });
    feasLevels.forEach(function (L) { wSumF[L] = 0; wCountF[L] = 0; });
    var baseBins = 20, baseHist = new Array(baseBins).fill(0);
    var sumBase = 0, countBase = 0, sumE = 0, countE = 0, sevCount = {};
    SC().cvssSeverity.forEach(function (s) { sevCount[s.label] = 0; });
    var caseCount = {}; CASE_ORDER.forEach(function (c) { caseCount[c] = 0; });
    var criticalVehicles = 0, sumProb = 0;

    for (var vi = 0; vi < p.vehicles; vi++) {
      /* Per-vehicle probability: seeded random feature set in "featuresRandom". */
      var vProb = (p.vulnProbMode === "featuresRandom")
        ? probRule(vulnProbFromFeatures(randomFeatureSelection(rng))) : fixedProb;
      sumProb += vProb;

      var ecus = [];
      for (var ei = 0; ei < p.ecuCount; ei++) ecus.push(genEcu(rng, p, groups, vProb, ei));
      var res = VRA.vehicle.rateSet(ecus);

      var comp = { Negligible: 0, Moderate: 0, Major: 0, Severe: 0 }, findings = 0;
      res.rows.forEach(function (r) {
        comp[r.impact.baseLabel] = (comp[r.impact.baseLabel] || 0) + 1;
        wSum[r.impact.label]  += r.weight; wCount[r.impact.label]  += 1;
        wSumF[r.feasibility.label] += r.weight; wCountF[r.feasibility.label] += 1;
        if (wHist[r.weight] != null) wHist[r.weight] += 1;
        if (h8Count[r.impact.label]) h8Count[r.impact.label][r.feasibility.label] += 1;
        var worst = 0;
        (r.ecu.findings || []).forEach(function (f) {
          findings++; if (f.cvss > worst) worst = f.cvss;
          sumBase += f.cvss; countBase++;
          baseHist[Math.min(baseBins - 1, Math.floor(f.cvss / (10 / baseBins)))]++;
          sevCount[cvssSeverity(f.cvss).label]++;
          var E = VRA.vehicle.exploitability(f); if (E != null) { sumE += E; countE++; }
        });
        var caseLabel = caseLabelOf(VRA.component.starScore(r.ecu.findings));
        caseCount[caseLabel]++;
        if (components) components.push({
          v: vi, name: r.ecu.name, domain: r.ecu.domain, asil: r.ecu.asil,
          pia: r.ecu.pia ? 1 : 0, net: r.ecu.netInteraction,
          k: (r.ecu.findings || []).length, worst: worst,
          E: r.feasibility.E, feas: r.feasibility.label, imp: r.impact.label,
          w: r.weight, s: r.critical ? "CRIT" : r.starScore, starCase: caseLabel
        });
      });
      if (res.criticals.length) criticalVehicles++;

      ratings.push(res.R);
      vehicles.push({
        id: vi, R: res.R, stars: Math.round(res.R), ecus: ecus.length,
        findings: findings, criticals: res.criticals.length,
        sumSW: res.sumSW, sumW: res.sumW, comp: comp, vulnProb: vProb
      });
    }

    return {
      params: p,
      ratings: ratings,
      vehicles: vehicles,
      components: components,                       // null when fleet exceeds maxComponentRecords
      stats: computeStats(ratings),
      histogram: buildHistogram(ratings, p.bins),
      weightByImpact: impactLevels.map(function (L) {
        return { label: L, mean: wCount[L] ? wSum[L] / wCount[L] : 0, n: wCount[L] };
      }),
      weightByFeasibility: feasLevels.map(function (L) {
        return { label: L, mean: wCountF[L] ? wSumF[L] / wCountF[L] : 0, n: wCountF[L] };
      }),
      weightHistogram: [1, 2, 3, 4, 5].map(function (wv) { return { weight: wv, count: wHist[wv] }; }),
      h8Matrix: impactLevels.map(function (L) {
        var row = SC().h8[L] || [];
        return {
          impact: L,
          cells: feasLevels.map(function (F, ci) { return { feasibility: F, weight: row[ci], count: h8Count[L][F] }; })
        };
      }),
      cvss: {
        meanBase: countBase ? sumBase / countBase : 0,
        meanE: countE ? sumE / countE : 0,
        nFindings: countBase,
        hist: baseHist.map(function (c, k) { return { x0: k * (10 / baseBins), x1: (k + 1) * (10 / baseBins), count: c }; }),
        severity: SC().cvssSeverity.map(function (s) { return { label: s.label, color: s.color, count: sevCount[s.label] }; })
      },
      criticalRate: p.vehicles ? criticalVehicles / p.vehicles : 0,
      vulnProbUsed: p.vehicles ? sumProb / p.vehicles : 0,
      caseCoverage: CASE_ORDER.map(function (c) { return { label: c, count: caseCount[c] }; }),
      warning: warning
    };
  }

  /* ===========================================================================
   * 8. STATISTICS + HISTOGRAM
   * =========================================================================*/
  function computeStats(xs) {
    if (!xs.length) return { n: 0, min: 0, max: 0, mean: 0, std: 0, median: 0, p5: 0, p95: 0, stars: [0, 0, 0, 0, 0] };
    var n = xs.length, min = Infinity, max = -Infinity, sum = 0, i;
    for (i = 0; i < n; i++) { var x = xs[i]; if (x < min) min = x; if (x > max) max = x; sum += x; }
    var mean = sum / n, sq = 0;
    for (i = 0; i < n; i++) sq += (xs[i] - mean) * (xs[i] - mean);
    var stars = [0, 0, 0, 0, 0];
    for (i = 0; i < n; i++) { var s = Math.round(xs[i]); s = s < 1 ? 1 : s > 5 ? 5 : s; stars[s - 1]++; }
    /* Percentiles (nearest-rank on the sorted ratings) — distribution shape
     * beyond mean/std, so fleet claims aren't driven by outliers. */
    var sorted = xs.slice().sort(function (a, b) { return a - b; });
    function pct(p) { return sorted[Math.min(n - 1, Math.max(0, Math.ceil(p * n) - 1))]; }
    return { n: n, min: min, max: max, mean: mean, std: Math.sqrt(sq / n),
             median: pct(0.5), p5: pct(0.05), p95: pct(0.95), stars: stars };
  }

  function buildHistogram(xs, bins) {
    bins = bins || 20;
    var lo = 0, hi = 5, w = (hi - lo) / bins, counts = new Array(bins).fill(0), i;
    for (i = 0; i < xs.length; i++) {
      var b = Math.floor((xs[i] - lo) / w); if (b < 0) b = 0; if (b >= bins) b = bins - 1;
      counts[b]++;
    }
    return counts.map(function (c, k) { return { x0: lo + k * w, x1: lo + (k + 1) * w, count: c }; });
  }

  /* ===========================================================================
   * 9. CSV EXPORT  (per vehicle + per component — replicable via the seed)
   * =========================================================================*/
  function toCSV(result) {
    var seed = result.params.seed;
    var head = ["seed", "vehicle", "vuln_prob", "ecus", "findings", "criticals",
                "n_negligible", "n_moderate", "n_major", "n_severe",
                "sum_sw", "sum_w", "R", "stars"];
    var lines = [head.join(",")];
    result.vehicles.forEach(function (v) {
      lines.push([seed, v.id, v.vulnProb.toFixed(2), v.ecus, v.findings, v.criticals,
        v.comp.Negligible, v.comp.Moderate, v.comp.Major, v.comp.Severe,
        v.sumSW.toFixed(2), v.sumW, v.R.toFixed(4), v.stars].join(","));
    });
    return lines.join("\n");
  }

  /** Raw per-component export (the old data.txt, now structured + seeded). */
  function toComponentCSV(result) {
    if (!result.components) return null;
    var seed = result.params.seed;
    var head = ["seed", "vehicle", "component", "domain", "asil", "pia",
                "net_interaction", "findings", "worst_cvss", "feasibility_E",
                "feasibility", "impact", "weight", "starScore", "case"];
    var lines = [head.join(",")];
    result.components.forEach(function (c) {
      lines.push([seed, c.v, c.name, c.domain, c.asil, c.pia, c.net,
        c.k, c.k ? c.worst.toFixed(1) : "", c.E == null ? "" : c.E.toFixed(2),
        c.feas, c.imp, c.w, (c.s === "CRIT" ? "CRIT" : c.s.toFixed(2)), c.starCase].join(","));
    });
    return lines.join("\n");
  }

  /* Chart data — one tidy, long-format CSV holding the series behind EVERY chart
   * in the panel, so each figure can be reproduced in LaTeX/pgfplots or pandas.
   * Columns: series, label, x_low, x_high, value. Histograms use x_low/x_high
   * (bin edges) with value = count; categorical series use label with value =
   * count or mean. Filter by `series` to plot one chart. */
  function toChartCSV(result) {
    var rows = [["series", "label", "x_low", "x_high", "value"]];
    function push(series, label, xl, xh, val) { rows.push([series, label, xl, xh, val]); }

    result.histogram.forEach(function (b) {
      push("rating_distribution", "", b.x0.toFixed(3), b.x1.toFixed(3), b.count);
    });
    result.cvss.hist.forEach(function (b) {
      push("cvss_base_distribution", "", b.x0.toFixed(2), b.x1.toFixed(2), b.count);
    });
    result.cvss.severity.forEach(function (s) {
      push("cvss_severity", s.label, "", "", s.count);
    });
    result.weightByImpact.forEach(function (b) {
      push("mean_weight_by_impact", b.label, "", "", b.mean.toFixed(4));
      push("count_by_impact", b.label, "", "", b.n);
    });
    result.weightByFeasibility.forEach(function (b) {
      push("mean_weight_by_feasibility", b.label, "", "", b.mean.toFixed(4));
      push("count_by_feasibility", b.label, "", "", b.n);
    });
    (result.weightHistogram || []).forEach(function (b) {
      push("weight_distribution", "w=" + b.weight, b.weight, b.weight, b.count);
    });
    (result.stats.stars || []).forEach(function (c, i) {
      push("star_distribution", (i + 1) + "star", i + 1, i + 1, c);
    });
    result.caseCoverage.forEach(function (c) {
      push("case_coverage", c.label, "", "", c.count);
    });
    (result.h8Matrix || []).forEach(function (row) {
      row.cells.forEach(function (c) {
        push("h8_matrix", row.impact + "|" + c.feasibility, c.weight, c.weight, c.count);
      });
    });
    return rows.map(function (r) { return r.join(","); }).join("\n");
  }

  function download(name, text) {
    if (typeof Blob === "undefined" || typeof URL === "undefined" || !URL.createObjectURL) return false;
    var blob = new Blob([text], { type: "text/csv" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 0);
    return true;
  }

  /* ===========================================================================
   * 10. VERIFICATION & VALIDATION
   * =========================================================================*/
  function check(desc, expected, got, ref) {
    return { desc: desc, expected: String(expected), got: String(got), pass: String(expected) === String(got), ref: ref };
  }
  function round2(x) { return Math.round((x + 1e-9) * 100) / 100; }
  /** Same distribution row for every domain (test helper). */
  function sameForAllDomains(row) { var o = {}; CFG().domains.forEach(function (d) { o[d.id] = row.slice(); }); return o; }
  function monotoneUp(a) { for (var i = 1; i < a.length; i++) if (a[i] < a[i - 1] - 1e-9) return false; return true; }

  function verify() {
    var groups = [];

    /* (a) CVSS v3.1 base-score formula reproduces the official calculator. */
    groups.push({
      name: "CVSS v3.1 base score  (matches the calculator)", ref: "FIRST CVSS v3.1 \u00A77.1 \u00B7 NVD",
      cases: [
        check("CVE-2018-20342 P/L/N/N \u00B7 C/I/A=H (S:U) \u2192 6.8", "6.8",
          cvssBase({ av: "P", ac: "L", pr: "N", ui: "N", c: "H", i: "H", a: "H" })),
        check("CVE-2019-18827 N/H/N/N \u00B7 C=H (S:U) \u2192 5.9", "5.9",
          cvssBase({ av: "N", ac: "H", pr: "N", ui: "N", c: "H", i: "N", a: "N" })),
        check("CVE-2018-17977 L/L/H/N \u00B7 A=H (S:U) \u2192 4.4", "4.4",
          cvssBase({ av: "L", ac: "L", pr: "H", ui: "N", c: "N", i: "N", a: "H" })),
        check("CVE-2017-5579 L/L/L/N \u00B7 A=H (S:C) \u2192 6.5", "6.5",
          cvssBase({ av: "L", ac: "L", pr: "L", ui: "N", c: "N", i: "N", a: "H", scope: "C" })),
        check("worst N/L/N/N \u00B7 C/I/A=H (S:U) \u2192 9.8", "9.8",
          cvssBase({ av: "N", ac: "L", pr: "N", ui: "N", c: "H", i: "H", a: "H" })),
        check("no impact (C/I/A=N) \u2192 0.0", "0",
          cvssBase({ av: "N", ac: "L", pr: "N", ui: "N", c: "N", i: "N", a: "N" }))
      ]
    });

    /* (a2) Qualitative severity scale. */
    groups.push({
      name: "CVSS severity scale  (base score \u2192 label)", ref: "FIRST CVSS v3.1 \u00A75",
      cases: [
        check("0.0 \u2192 None",     "None",     cvssSeverity(0.0).label),
        check("3.9 \u2192 Low",      "Low",      cvssSeverity(3.9).label),
        check("6.9 \u2192 Medium",   "Medium",   cvssSeverity(6.9).label),
        check("7.0 \u2192 High",     "High",     cvssSeverity(7.0).label),
        check("9.8 \u2192 Critical", "Critical", cvssSeverity(9.8).label)
      ]
    });

    /* (b) Boundary correctness — the enumerated pool. */
    var full = buildVulnPool(0, 10);
    var minB = Infinity, maxB = -Infinity;
    full.forEach(function (v) { if (v.base < minB) minB = v.base; if (v.base > maxB) maxB = v.base; });
    var narrow = buildVulnPool(4.0, 4.4);
    var narrowOK = narrow.length > 0 && narrow.every(function (v) { return v.base >= 4.0 && v.base <= 4.4; });
    var emptyRun = run({ vehicles: 30, seed: 5, vulnProbability: 1, vulnRange: [0.1, 1.5], vulnProbMode: "manual" });
    var swapped = run({ vehicles: 30, seed: 5, vulnProbability: 1, vulnRange: [6.9, 4.0], vulnProbMode: "manual" });
    var swappedOK = swapped.cvss.nFindings > 0 && swapped.params.vulnRange[0] === 4.0 && swapped.params.vulnRange[1] === 6.9;
    groups.push({
      name: "Boundary correctness  (exact achievable-score pool)", ref: "discrete v3.1 base scores",
      cases: [
        check("achievable positive scores span 1.6\u20139.8", "1.6\u20139.8", minB + "\u2013" + maxB),
        check("narrow range [4.0, 4.4] \u2192 all in range", "true", String(narrowOK)),
        check("unachievable [0.1, 1.5] \u2192 reported, 0 vulns", "true",
          String(!!emptyRun.warning && emptyRun.cvss.nFindings === 0)),
        check("inverted [6.9, 4.0] \u2192 normalised to [4.0, 6.9]", "true", String(swappedOK))
      ]
    });

    /* (c) Security features → vulnerability probability. */
    var allIds = [];
    SIM().securityFeatures.catalogue.forEach(function (f) {
      if (f.options) allIds.push(f.options[0].id); else allIds.push(f.id);
    });
    groups.push({
      name: "Security features \u2192 vuln. probability  (ported catalogue)", ref: "base 1.0, floor 0.05, exclusive groups",
      cases: [
        check("no features \u2192 1.00", "1", vulnProbFromFeatures([])),
        check("all strongest features \u2192 floor 0.05", "0.05", vulnProbFromFeatures(allIds)),
        check("group exclusivity: Full+Medium HSM \u2261 Full only",
          String(vulnProbFromFeatures(["hsm-full"])), String(vulnProbFromFeatures(["hsm-full", "hsm-medium"]))),
        check("single feature: Secure Boot \u2192 0.94", "0.94", vulnProbFromFeatures(["secure-boot"]))
      ]
    });

    /* (c-b) The 5% probability rule: 0 stays 0, anything in (0, 5%) snaps to 5%. */
    function usedProb(pr) { return run({ vehicles: 20, seed: 3, vulnProbability: pr, vulnProbMode: "manual" }).vulnProbUsed; }
    groups.push({
      name: "Vulnerability-probability rule  (0 or \u2265 5%)", ref: "residual 5% floor \u00B7 1\u20134% invalid",
      cases: [
        check("0% stays 0% (clean fleet)", "0.00", usedProb(0).toFixed(2)),
        check("3% is raised to 5%", "0.05", usedProb(0.03).toFixed(2)),
        check("1% is raised to 5%", "0.05", usedProb(0.01).toFixed(2)),
        check("5% stays 5%", "0.05", usedProb(0.05).toFixed(2)),
        check("24% stays 24%", "0.24", usedProb(0.24).toFixed(2))
      ]
    });

    /* (d) Replicability — same seed ⇒ identical fleet (incl. random features). */
    var r1 = run({ vehicles: 150, seed: 777, vulnProbMode: "featuresRandom" });
    var r2 = run({ vehicles: 150, seed: 777, vulnProbMode: "featuresRandom" });
    var r3 = run({ vehicles: 150, seed: 778, vulnProbMode: "featuresRandom" });
    groups.push({
      name: "Replicability  (seeded PRNG)", ref: "mulberry32(seed)",
      cases: [
        check("same seed \u2192 identical ratings", "true",
          String(r1.ratings.every(function (x, k) { return x === r2.ratings[k]; }))),
        check("different seed \u2192 different fleet", "true",
          String(r1.ratings.some(function (x, k) { return x !== r3.ratings[k]; }))),
        check("fleet size honoured", "150", r1.ratings.length)
      ]
    });

    /* (e) The 0% proof + rating bounds.
     * 0% vulnerability probability MUST give exactly 5 stars for EVERY
     * vehicle — the model's cornerstone property (no finding → full starScore →
     * R = Σ(5·w)/Σ(w) = 5 regardless of weights). Checked as min = max = 5. */
    var clean = run({ vehicles: 200, vulnProbability: 0, piaProbability: 0, seed: 5, vulnProbMode: "manual" });
    var zeroExact = clean.stats.min === 5 && clean.stats.max === 5 && clean.stats.stars[4] === 200;
    var zeroKept = clean.params.vulnProbability === 0 && clean.vulnProbUsed === 0;
    var noEcus = run({ vehicles: 25, ecuCount: 0, seed: 3 });
    var inRange = run({ vehicles: 200, seed: 9 }).ratings.every(function (x) { return x >= 0 && x <= 5; });
    groups.push({
      name: "The 0% proof + rating bounds", ref: "no finding \u2192 starScore 5 \u2192 R = 5 exactly",
      cases: [
        check("0% vulns \u2192 EVERY vehicle exactly 5\u2605 (min = max = 5.00)", "true", String(zeroExact)),
        check("manual 0% is honoured, never floored", "true", String(zeroKept)),
        check("0 ECUs \u2192 R = 5, no NaN", "true",
          String(noEcus.stats.min === 5 && noEcus.stats.max === 5 && !isNaN(noEcus.stats.std))),
        check("all ratings within [0, 5]", "true", String(inRange)),
        check("percentiles ordered: min ≤ P5 ≤ median ≤ P95 ≤ max", "true", (function () {
          var st = run({ vehicles: 300, seed: 9 }).stats;
          return String(st.min <= st.p5 && st.p5 <= st.median && st.median <= st.p95 && st.p95 <= st.max);
        })())
      ]
    });

    /* (g2) Completeness of inputs — extremes and monotonicity. */
    var full1 = run({ vehicles: 60, seed: 8, vulnProbability: 1, vulnProbMode: "manual" });
    var everyHasFinding = full1.components.every(function (c) { return c.k >= 1; });
    /* PIA monotonicity: identical fleets except the PIA flag (same seed, same
     * rng consumption) — promotions can only raise Table H.8 weights. */
    function totalW(r) { return r.vehicles.reduce(function (a, v) { return a + v.sumW; }, 0); }
    var pia0 = run({ vehicles: 120, seed: 31, piaProbability: 0, vulnProbability: 0.4, vulnProbMode: "manual" });
    var pia1 = run({ vehicles: 120, seed: 31, piaProbability: 1, vulnProbability: 0.4, vulnProbMode: "manual" });
    groups.push({
      name: "Completeness of inputs  (extremes & monotonicity)", ref: "degenerate settings behave exactly",
      cases: [
        check("probability 1 \u2192 every component has \u2265 1 finding", "true", String(everyHasFinding)),
        check("PIA 0% \u2192 no impact promotions consumed", "true",
          String(pia0.vehicles.every(function (v, i) { return v.sumW <= pia1.vehicles[i].sumW; }))),
        check("PIA promotions only raise total weight (\u03A3w monotone)", "true", String(totalW(pia1) >= totalW(pia0))),
        check("configurable ASIL mix changes the fleet (all-Severe < all-QM)", "true", (function () {
          var hi = run({ vehicles: 200, seed: 5, vulnProbability: 0.5, vulnProbMode: "manual", asilByDomain: sameForAllDomains([0, 0, 0, 0, 1]) });
          var lo = run({ vehicles: 200, seed: 5, vulnProbability: 0.5, vulnProbMode: "manual", asilByDomain: sameForAllDomains([1, 0, 0, 0, 0]) });
          return String(hi.stats.mean < lo.stats.mean);
        })())
      ]
    });

    /* (f) Prioritisation — both Table H.8 axes (design intent). */
    var hi5 = run({ vehicles: 250, seed: 42, vulnProbability: 0.5, piaProbability: 0, vulnProbMode: "manual",
      asilByDomain: sameForAllDomains([0, 0, 0, 0, 1]) });
    var lo5 = run({ vehicles: 250, seed: 42, vulnProbability: 0.5, piaProbability: 0, vulnProbMode: "manual",
      asilByDomain: sameForAllDomains([1, 0, 0, 0, 0]) });
    var mono = run({ vehicles: 400, seed: 3 });
    groups.push({
      name: "Prioritisation  (both H.8 axes, design intent)", ref: "ASIL \u2192 impact \u00B7 CVSS E \u2192 feasibility",
      cases: [
        check("Severe-heavy fleet rates below Negligible-heavy", "true",
          String(hi5.stats.mean < lo5.stats.mean), round2(hi5.stats.mean) + " < " + round2(lo5.stats.mean)),
        check("mean weight increases Negligible\u2192Severe", "true",
          String(monotoneUp(mono.weightByImpact.map(function (b) { return b.mean; })))),
        check("mean weight increases Very Low\u2192High", "true",
          String(monotoneUp(mono.weightByFeasibility.map(function (b) { return b.mean; }))))
      ]
    });

    /* (g) Populated Table H.8 + weight distribution — the new fleet aggregates
     * must be internally consistent: every component lands in exactly one cell,
     * each cell's weight equals config H.8, and the weight histogram agrees. */
    var hm = run({ vehicles: 300, seed: 9, vulnProbability: 0.5, vulnProbMode: "manual" });
    var cellTotal = 0, cellWeightsOK = true;
    hm.h8Matrix.forEach(function (row) {
      row.cells.forEach(function (c, ci) { cellTotal += c.count; if (c.weight !== SC().h8[row.impact][ci]) cellWeightsOK = false; });
    });
    var whTotal = hm.weightHistogram.reduce(function (a, b) { return a + b.count; }, 0);
    var expectedComponents = hm.stats.n * hm.params.ecuCount;
    groups.push({
      name: "Populated H.8 matrix + weight distribution", ref: "Annex H Table H.8 \u00B7 fleet aggregates",
      cases: [
        check("matrix cell counts sum to N\u00D7ECU", String(expectedComponents), String(cellTotal)),
        check("every cell weight equals config H.8", "true", String(cellWeightsOK)),
        check("weight histogram sums to N\u00D7ECU", String(expectedComponents), String(whTotal))
      ]
    });

    /* (h) Rule harmony — end-to-end consistency of every generated artefact. */
    var h = run({ vehicles: 120, seed: 77, vulnProbability: 0.6, vulnProbMode: "manual" });
    var weightsOK = h.components.every(function (c) { return c.w >= 1 && c.w <= SC().weightMax; });
    var scoresOK = h.components.every(function (c) { return c.s === "CRIT" || (c.s >= 0 && c.s <= 5); });
    var feasOK = h.components.every(function (c) { return SC().feasibilityLevels.indexOf(c.feas) !== -1; });
    groups.push({
      name: "Rule harmony  (all rules consistent end-to-end)", ref: "generated fleet audit",
      cases: [
        check("cap 6.9 \u2192 no critical components ever", "0", h.criticalRate),
        check("every weight w \u2208 [1, 5]", "true", String(weightsOK)),
        check("every star score s \u2208 [0, 5] (or CRIT)", "true", String(scoresOK)),
        check("every feasibility is a valid G.8 band", "true", String(feasOK))
      ]
    });

    /* (i) Case coverage — every Algorithm 1 branch is exercised.
     * A below-5.3 fleet with up to 3 distinct-category findings must reach
     * Case 1, Case 2 AND Case 3; a fleet allowing ≥5.3 must reach Worst-case;
     * the 6.9 cap keeps Critical at zero. */
    function caseCountsOf(res) { var o = {}; res.caseCoverage.forEach(function (c) { o[c.label] = c.count; }); return o; }
    var below = caseCountsOf(run({ vehicles: 400, seed: 21, vulnProbability: 1, findingsPerEcu: [1, 3], vulnRange: [0.1, 5.2] }));
    var fullRange = caseCountsOf(run({ vehicles: 400, seed: 21, vulnProbability: 1, findingsPerEcu: [1, 3], vulnRange: [0.1, 6.9] }));
    groups.push({
      name: "Case coverage  (all Algorithm 1 branches)", ref: "component star score \u00B7 cases 1/2/3 + worst",
      cases: [
        check("below-5.3 fleet reaches Case 1", "true", String(below["Case 1"] > 0)),
        check("below-5.3 fleet reaches Case 2", "true", String(below["Case 2"] > 0)),
        check("below-5.3 fleet reaches Case 3", "true", String(below["Case 3"] > 0)),
        check("below-5.3 fleet has no Worst-case", "0", below["Worst-case"]),
        check("full-range fleet reaches Worst-case", "true", String(fullRange["Worst-case"] > 0)),
        check("6.9 cap \u2192 zero Critical components", "0", fullRange.Critical)
      ]
    });

    /* (j) Scalability — the same rules hold and the mean stays stable as the
     * ECU count grows from a small car to a 100-ECU one. */
    var sweep = scalabilitySweep({ seed: 21434, vulnProbability: 0.24, vulnRange: [0.1, 6.9] });
    groups.push({
      name: "Scalability  (mean rating vs ECU count)", ref: "1 to 100 ECUs \u00B7 same pipeline",
      cases: [
        check("every point is a valid rating in [0, 5]", "true",
          String(sweep.every(function (p) { return p.meanR >= 0 && p.meanR <= 5; }))),
        check("sweep spans 1 to 100 ECUs", "1..100", sweep[0].ecuCount + ".." + sweep[sweep.length - 1].ecuCount),
        check("mean stabilises at scale (|R100 \u2212 R50| < 0.15)", "true",
          String(Math.abs(sweep[sweep.length - 1].meanR - sweep[sweep.length - 2].meanR) < 0.15))
      ]
    });

    return groups;
  }

  /* ===========================================================================
   * 11. RENDERING  (charts unchanged; controls + notices extended)
   * =========================================================================*/
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
  var MONO = "ui-monospace,monospace";
  /* ---- CHART COLOUR STANDARD -------------------------------------------------
   * One palette across every chart. QUALITY_RAMP runs worst (red) to best (green),
   * colourblind-tuned (RdYlGn), used wherever a value carries severity/quality:
   *   rating bins (0-1 red ... 4-5 green), CVSS severity (config), and the Table
   *   H.8 weight (WEIGHT_COLOR below is the same ramp reversed, since a high weight
   *   is bad). Trend lines and reference markers stay a neutral teal (#084b52), and
   *   a value's number label is always shown as a second, colour-independent cue. */
  var QUALITY_RAMP = ["#a50026", "#f46d43", "#fee08b", "#a6d96a", "#1a9850"]; // worst → best
  var NEUTRAL = "#084b52";

  /** Horizontal gridlines + y-axis labels (shared by all charts). */
  function yGrid(x0, y0, iw, ih, divs, labelFn) {
    var out = "";
    for (var g = 0; g <= divs; g++) {
      var gy = y0 + ih - (ih * g / divs);
      out += "<line x1='" + x0 + "' y1='" + gy + "' x2='" + (x0 + iw) + "' y2='" + gy + "' stroke='#e8ebef'/>";
      out += "<text x='" + (x0 - 6) + "' y='" + (gy + 3) + "' text-anchor='end' font-size='9' fill='#98a2ad' font-family='" + MONO + "'>" + labelFn(g) + "</text>";
    }
    return out;
  }
  /** Standard chart wrapper. */
  function svgWrap(W, H, aria, body) {
    return "<svg viewBox='0 0 " + W + " " + H + "' width='100%' style='height:auto;display:block' role='img' aria-label='" + aria + "'>" +
      "<rect width='" + W + "' height='" + H + "' fill='#fbfcfd'/>" + body + "</svg>";
  }

  function chartHistogram(result) {
    var h = result.histogram, st = result.stats;
    var W = 640, H = 260, padL = 40, padR = 14, padT = 14, padB = 34;
    var iw = W - padL - padR, ih = H - padT - padB;
    var maxC = Math.max.apply(null, h.map(function (b) { return b.count; })) || 1;
    var bw = iw / h.length;
    var svg = yGrid(padL, padT, iw, ih, 4, function (g) { return Math.round(maxC * g / 4); });
    var starColor = QUALITY_RAMP;
    h.forEach(function (b, k) {
      var bh = ih * b.count / maxC, x = padL + k * bw, y = padT + ih - bh;
      var mid = (b.x0 + b.x1) / 2, band = Math.min(4, Math.max(0, Math.round(mid) - 1));
      svg += "<rect x='" + (x + 0.5) + "' y='" + y + "' width='" + (bw - 1) + "' height='" + bh + "' fill='" + starColor[band] + "' opacity='0.85'/>";
    });
    for (var t = 0; t <= 5; t++) {
      var tx = padL + iw * t / 5;
      svg += "<line x1='" + tx + "' y1='" + (padT + ih) + "' x2='" + tx + "' y2='" + (padT + ih + 4) + "' stroke='#b6bec8'/>";
      svg += "<text x='" + tx + "' y='" + (padT + ih + 16) + "' text-anchor='middle' font-size='9.5' fill='#5a6472' font-family='ui-monospace,monospace'>" + t + "\u2605</text>";
    }
    function vline(val, color, label, dy) {
      var x = padL + iw * val / 5;
      svg += "<line x1='" + x + "' y1='" + padT + "' x2='" + x + "' y2='" + (padT + ih) + "' stroke='" + color + "' stroke-width='1.6' stroke-dasharray='4 3'/>";
      svg += "<text x='" + x + "' y='" + (padT + 10 + dy) + "' text-anchor='middle' font-size='9' font-weight='700' fill='" + color + "' font-family='ui-monospace,monospace'>" + label + "</text>";
    }
    vline(st.min, QUALITY_RAMP[0], "min " + st.min.toFixed(2), 0);
    vline(st.mean, NEUTRAL, "mean " + st.mean.toFixed(2), 12);
    vline(st.max, QUALITY_RAMP[4], "max " + st.max.toFixed(2), 0);
    svg += "<text x='" + padL + "' y='" + (H - 4) + "' font-size='9' fill='#98a2ad' font-family='" + MONO + "'>vehicles per rating bin (n = " + st.n.toLocaleString() + ")</text>";
    return svgWrap(W, H, "Vehicle rating distribution", svg);
  }

  /* ECU-count scalability sweep: mean rating across the fleet at growing ECU
   * counts, showing the same rules hold from a small car to a 100-ECU one. */
  function chartScalability(sweep) {
    var W = 640, H = 260, padL = 44, padR = 16, padT = 18, padB = 42;
    var iw = W - padL - padR, ih = H - padT - padB;
    var xs = sweep.map(function (p) { return p.ecuCount; });
    var maxX = Math.max.apply(null, xs) || 1;
    var svg = yGrid(padL, padT, iw, ih, 5, function (g) { return g; });
    function px(x) { return padL + iw * (x / maxX); }
    function py(v) { return padT + ih * (1 - v / 5); }
    // x-axis ticks
    sweep.forEach(function (p) {
      svg += "<text x='" + px(p.ecuCount) + "' y='" + (padT + ih + 15) + "' text-anchor='middle' font-size='9' fill='#3a4550' font-family='" + MONO + "'>" + p.ecuCount + "</text>";
    });
    // line + points
    var d = sweep.map(function (p, i) { return (i ? "L" : "M") + px(p.ecuCount).toFixed(1) + "," + py(p.meanR).toFixed(1); }).join(" ");
    svg += "<path d='" + d + "' fill='none' stroke='" + NEUTRAL + "' stroke-width='2.2'/>";
    sweep.forEach(function (p) {
      svg += "<circle cx='" + px(p.ecuCount) + "' cy='" + py(p.meanR) + "' r='3.4' fill='" + NEUTRAL + "'/>";
      svg += "<text x='" + px(p.ecuCount) + "' y='" + (py(p.meanR) - 8) + "' text-anchor='middle' font-size='8.5' font-weight='700' fill='" + NEUTRAL + "' font-family='" + MONO + "'>" + p.meanR.toFixed(2) + "</text>";
    });
    svg += "<text x='" + padL + "' y='" + (H - 3) + "' font-size='9' fill='#98a2ad' font-family='" + MONO + "'>mean vehicle rating vs ECU count (same rules, yesterday to tomorrow)</text>";
    return svgWrap(W, H, "ECU-count scalability", svg);
  }

  /* Weight-sensitivity: how little R moves when the slope and every Table H.8
   * weight are perturbed by a percentage. A flat line means the rating does not
   * hinge on the exact weight values. */
  function chartSensitivity(sens) {
    var pts = sens.points, W = 640, H = 260, padL = 44, padR = 16, padT = 18, padB = 44;
    var iw = W - padL - padR, ih = H - padT - padB;
    var svg = yGrid(padL, padT, iw, ih, 5, function (g) { return g; });
    var n = pts.length;
    function px(i) { return padL + iw * (i / (n - 1)); }
    function py(v) { return padT + ih * (1 - v / 5); }
    // baseline band (min..max) to show the spread is small
    var yTop = py(sens.max), yBot = py(sens.min);
    svg += "<rect x='" + padL + "' y='" + yTop + "' width='" + iw + "' height='" + (yBot - yTop) + "' fill='rgba(8,75,82,0.08)'/>";
    pts.forEach(function (p, i) {
      svg += "<text x='" + px(i) + "' y='" + (padT + ih + 15) + "' text-anchor='middle' font-size='8.5' fill='#3a4550' font-family='" + MONO + "'>" + (p.pct > 0 ? "+" : "") + p.pct + "%</text>";
    });
    var d = pts.map(function (p, i) { return (i ? "L" : "M") + px(i).toFixed(1) + "," + py(p.R).toFixed(1); }).join(" ");
    svg += "<path d='" + d + "' fill='none' stroke='" + NEUTRAL + "' stroke-width='2.2'/>";
    pts.forEach(function (p, i) {
      svg += "<circle cx='" + px(i) + "' cy='" + py(p.R) + "' r='3.2' fill='" + (p.pct === 0 ? QUALITY_RAMP[0] : NEUTRAL) + "'/>";
    });
    svg += "<text x='" + padL + "' y='" + (H - 3) + "' font-size='9' fill='#98a2ad' font-family='" + MONO + "'>R vs \u00B120% change in slope + Table H.8 weights (spread " + sens.spread.toFixed(2) + " on a 0\u20135 scale)</text>";
    return svgWrap(W, H, "weight sensitivity", svg);
  }
  /* Weight palette: green (low risk) to red (high risk) for severity, but tuned
   * to stay colourblind-safe. The low end is a bluish teal-green and the high end
   * a dark red, so the two ends differ in HUE and in LUMINANCE (light-ish to dark),
   * which keeps them apart for red-green colourblind viewers and in greyscale. The
   * w=1..5 number labels are a second, colour-independent cue. */
  var WEIGHT_COLOR = { 1: "#1a9850", 2: "#a6d96a", 3: "#fee08b", 4: "#f46d43", 5: "#a50026" };
  function chartWeightHistogram(r) {
    var data = r.weightHistogram || [], W = 640, H = 260, padL = 40, padR = 14, padT = 14, padB = 46;
    var iw = W - padL - padR, ih = H - padT - padB;
    var maxC = Math.max.apply(null, data.map(function (d) { return d.count; })) || 1;
    var slot = iw / (data.length || 1), bw = Math.min(70, slot * 0.6);
    var total = data.reduce(function (a, d) { return a + d.count; }, 0) || 1;
    var svg = yGrid(padL, padT, iw, ih, 4, function (g) { return Math.round(maxC * g / 4); });
    data.forEach(function (d, k) {
      var bh = ih * d.count / maxC, x = padL + k * slot + (slot - bw) / 2, y = padT + ih - bh;
      svg += "<rect x='" + x + "' y='" + y + "' width='" + bw + "' height='" + bh + "' rx='3' fill='" + (WEIGHT_COLOR[d.weight] || "#888") + "' stroke='#cbb59f' stroke-width='0.8'/>";
      svg += "<text x='" + (x + bw / 2) + "' y='" + (y - 5) + "' text-anchor='middle' font-size='10' font-weight='700' fill='#26303b' font-family='ui-monospace,monospace'>" + (100 * d.count / total).toFixed(1) + "%</text>";
      svg += "<text x='" + (x + bw / 2) + "' y='" + (padT + ih + 15) + "' text-anchor='middle' font-size='10' fill='#3a4550' font-family='ui-monospace,monospace'>w=" + d.weight + "</text>";
      svg += "<text x='" + (x + bw / 2) + "' y='" + (padT + ih + 27) + "' text-anchor='middle' font-size='8' fill='#98a2ad' font-family='ui-monospace,monospace'>n=" + d.count.toLocaleString() + "</text>";
    });
    svg += "<text x='" + padL + "' y='" + (H - 3) + "' font-size='9' fill='#98a2ad' font-family='" + MONO + "'>Table H.8 weight w assigned across all components</text>";
    return svgWrap(W, H, "weight distribution", svg);
  }

  /* Populated Table H.8: impact (rows, from ASIL) × feasibility (columns, from
   * CVSS E). Each cell is coloured by its H.8 weight on a green (w=1, low risk)
   * to red (w=5, high risk) scale, with intensity scaled by how many components
   * land there; the count and weight are printed in high-contrast text. */
  var WEIGHT_RGB = { 1: [26, 152, 80], 2: [166, 217, 106], 3: [254, 224, 139], 4: [244, 109, 67], 5: [165, 0, 38] };
  /* Luminance of an RGB laid over white at opacity a (for choosing text colour). */
  function lumOver(rgb, a) {
    var R = a * rgb[0] + (1 - a) * 255, G = a * rgb[1] + (1 - a) * 255, B = a * rgb[2] + (1 - a) * 255;
    return 0.299 * R + 0.587 * G + 0.114 * B;
  }
  function chartH8Matrix(r) {
    var m = r.h8Matrix || [], cols = SC().feasibilityLevels;
    var W = 640, H = 286, padL = 96, padR = 16, padT = 34, padB = 40;
    var gw = (W - padL - padR) / cols.length, gh = (H - padT - padB) / (m.length || 1);
    var maxC = 1;
    m.forEach(function (row) { row.cells.forEach(function (c) { if (c.count > maxC) maxC = c.count; }); });
    var svg = "";
    cols.forEach(function (F, ci) {
      svg += "<text x='" + (padL + ci * gw + gw / 2) + "' y='" + (padT - 18) + "' text-anchor='middle' font-size='9.5' font-weight='700' fill='#26303b' font-family='" + MONO + "'>" + F + "</text>";
    });
    svg += "<text x='" + (padL + (W - padL - padR) / 2) + "' y='" + (padT - 4) + "' text-anchor='middle' font-size='8' fill='#5a6472' font-family='" + MONO + "'>feasibility (CVSS E \u2192 Table G.8)</text>";
    m.forEach(function (row, ri) {
      svg += "<text x='" + (padL - 8) + "' y='" + (padT + ri * gh + gh / 2 + 3) + "' text-anchor='end' font-size='9.5' font-weight='700' fill='#26303b' font-family='" + MONO + "'>" + row.impact + "</text>";
      row.cells.forEach(function (c, ci) {
        var x = padL + ci * gw, y = padT + ri * gh;
        var t = c.count / maxC;
        var rgb = WEIGHT_RGB[c.weight] || [136, 136, 136];
        var alpha = 0.35 + 0.65 * t;                          // count intensity, floored so the weight tint always shows
        var light = lumOver(rgb, alpha) > 150;                // dark text on light cells, white on dark
        svg += "<rect x='" + (x + 1) + "' y='" + (y + 1) + "' width='" + (gw - 2) + "' height='" + (gh - 2) + "' rx='3' fill='rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + "," + alpha.toFixed(3) + ")' stroke='rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ",0.95)' stroke-width='0.6'/>";
        svg += "<text x='" + (x + gw / 2) + "' y='" + (y + gh / 2 - 1) + "' text-anchor='middle' font-size='11.5' font-weight='700' fill='" + (light ? "#1c2530" : "#ffffff") + "' font-family='" + MONO + "'>" + c.count.toLocaleString() + "</text>";
        svg += "<text x='" + (x + gw / 2) + "' y='" + (y + gh / 2 + 11) + "' text-anchor='middle' font-size='8' font-weight='700' fill='" + (light ? "#5a6472" : "#f0f0f0") + "' font-family='" + MONO + "'>w=" + c.weight + "</text>";
      });
    });
    svg += "<text x='12' y='" + (padT + (m.length ? m.length * gh / 2 : 0)) + "' text-anchor='middle' font-size='8' fill='#5a6472' font-family='" + MONO + "' transform='rotate(-90 12," + (padT + (m.length ? m.length * gh / 2 : 0)) + ")'>impact (ASIL)</text>";
    /* legend — weight scale, light (w=1, low risk) to dark (w=5, high risk) */
    var ly = H - 14, lx = padL;
    svg += "<text x='" + (lx - 8) + "' y='" + (ly + 8) + "' text-anchor='end' font-size='8' font-weight='700' fill='#5a6472' font-family='" + MONO + "'>weight w</text>";
    [1, 2, 3, 4, 5].forEach(function (wv) {
      var rgb = WEIGHT_RGB[wv], txt = lumOver(rgb, 1) > 150 ? "#3a3a20" : "#ffffff";
      svg += "<rect x='" + lx + "' y='" + ly + "' width='22' height='11' rx='2' fill='rgb(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ")'/>";
      svg += "<text x='" + (lx + 11) + "' y='" + (ly + 8.5) + "' text-anchor='middle' font-size='7.5' font-weight='700' fill='" + txt + "' font-family='" + MONO + "'>" + wv + "</text>";
      lx += 26;
    });
    svg += "<text x='" + (lx + 2) + "' y='" + (ly + 8) + "' font-size='7.5' fill='#98a2ad' font-family='" + MONO + "'>green = low risk \u2192 red = high (w-number is a second cue)</text>";
    return svgWrap(W, H, "populated Table H.8 matrix", svg);
  }

  function chartCvssBase(result) {
    var h = result.cvss.hist, sev = SC().cvssSeverity, W = 640, H = 260, padL = 40, padR = 14, padT = 14, padB = 46;
    var iw = W - padL - padR, ih = H - padT - padB;
    var maxC = Math.max.apply(null, h.map(function (b) { return b.count; })) || 1;
    var bw = iw / h.length;
    function colorFor(mid) { for (var i = 0; i < sev.length; i++) if (mid >= sev[i].min && mid <= sev[i].max) return sev[i].color; return "#888"; }
    var svg = yGrid(padL, padT, iw, ih, 4, function (g) { return Math.round(maxC * g / 4); });
    h.forEach(function (b, k) {
      var bh = ih * b.count / maxC, x = padL + k * bw, y = padT + ih - bh;
      svg += "<rect x='" + (x + 0.5) + "' y='" + y + "' width='" + (bw - 1) + "' height='" + bh + "' fill='" + colorFor((b.x0 + b.x1) / 2) + "' opacity='0.9'/>";
    });
    for (var t = 0; t <= 10; t += 2) {
      var tx = padL + iw * t / 10;
      svg += "<line x1='" + tx + "' y1='" + (padT + ih) + "' x2='" + tx + "' y2='" + (padT + ih + 4) + "' stroke='#b6bec8'/>";
      svg += "<text x='" + tx + "' y='" + (padT + ih + 15) + "' text-anchor='middle' font-size='9' fill='#5a6472' font-family='ui-monospace,monospace'>" + t + "</text>";
    }
    var mx = padL + iw * result.cvss.meanBase / 10;
    svg += "<line x1='" + mx + "' y1='" + padT + "' x2='" + mx + "' y2='" + (padT + ih) + "' stroke='" + NEUTRAL + "' stroke-width='1.6' stroke-dasharray='4 3'/>";
    svg += "<text x='" + mx + "' y='" + (padT + 10) + "' text-anchor='middle' font-size='9' font-weight='700' fill='" + NEUTRAL + "' font-family='ui-monospace,monospace'>mean " + result.cvss.meanBase.toFixed(2) + "</text>";
    var lx = padL;
    result.cvss.severity.forEach(function (s) {
      if (s.count === 0 && (s.label === "High" || s.label === "Critical")) return;
      svg += "<rect x='" + lx + "' y='" + (H - 12) + "' width='9' height='9' fill='" + s.color + "'/>";
      svg += "<text x='" + (lx + 12) + "' y='" + (H - 4) + "' font-size='8.5' fill='#5a6472' font-family='ui-monospace,monospace'>" + s.label + " " + s.count.toLocaleString() + "</text>";
      lx += 26 + (s.label.length + String(s.count).length) * 6;
    });
    return svgWrap(W, H, "CVSS base score distribution", svg);
  }

  function renderCaseCoverage(result) {
    var cases = result.caseCoverage, total = cases.reduce(function (a, c) { return a + c.count; }, 0) || 1;
    var colorOf = { "Clean": QUALITY_RAMP[4], "Case 1": QUALITY_RAMP[3], "Case 2": QUALITY_RAMP[2], "Case 3": QUALITY_RAMP[1], "Worst-case": QUALITY_RAMP[0], "Critical": "#6b0018" };
    var rows = cases.map(function (c) {
      var pct = (100 * c.count / total).toFixed(1);
      return "<div class='starrow'><span class='cl' style='color:" + colorOf[c.label] + "'>" + c.label + "</span>" +
        "<span class='sbar'><i style='width:" + pct + "%;background:" + colorOf[c.label] + "'></i></span>" +
        "<span class='sv'>" + c.count.toLocaleString() + " \u00B7 " + pct + "%</span></div>";
    }).join("");
    var reached = cases.filter(function (c) { return c.label.indexOf("Case") === 0 && c.count > 0; }).length;
    return "<div class='sim-stars'><div class='sim-ctitle'>Case coverage " +
      "<span class='ct-sub'>(Algorithm 1 branches \u00B7 " + reached + "/3 weighted cases reached)</span></div>" + rows + "</div>";
  }

  function renderStars(stats) {
    var total = stats.n || 1, out = "";
    stats.stars.forEach(function (c, i) {
      var pct = (100 * c / total).toFixed(1);
      out += "<div class='starrow'><span class='sl'>" + (i + 1) + "\u2605</span>" +
        "<span class='sbar'><i style='width:" + pct + "%'></i></span>" +
        "<span class='sv'>" + c.toLocaleString() + " \u00B7 " + pct + "%</span></div>";
    });
    return out;
  }

  function renderResult(result) {
    var s = result.stats, p = result.params, cv = result.cvss;
    var warn = result.warning
      ? "<div class='sim-warn'>\u26A0 " + esc(result.warning) + "</div>" : "";
    var snapped = p.vulnProbMode === "manual" && p.vulnProbability > 0 && p.vulnProbability < SC().starScore.residualFraction;
    var probLabel = p.vulnProbMode === "manual" ? (100 * result.vulnProbUsed).toFixed(0) + "%" + (snapped ? " (raised to 5%)" : "")
      : p.vulnProbMode === "features" ? (100 * result.vulnProbUsed).toFixed(0) + "% (features)"
      : "x\u0304 " + (100 * result.vulnProbUsed).toFixed(0) + "% (random)";
    var summary = "<div class='sim-stats'>" +
      stat("Vehicles", s.n.toLocaleString()) +
      stat("Mean", s.mean.toFixed(2) + " \u2605") +
      stat("Min", s.min.toFixed(2)) +
      stat("Max", s.max.toFixed(2)) +
      stat("Std dev", s.std.toFixed(2)) +
      stat("Median", s.median.toFixed(2)) +
      stat("P5–P95", s.p5.toFixed(2) + "–" + s.p95.toFixed(2)) +
      stat("Vuln prob", probLabel) +
      stat("Mean CVSS", cv.meanBase.toFixed(2)) +
      stat("Mean E", cv.meanE.toFixed(2)) +
      stat("Seed", p.seed) + "</div>";

    return warn + summary +
      "<div class='sim-charts'>" +
        "<div class='sim-chart'><div class='sim-ctitle'>Vehicle rating distribution</div>" + chartHistogram(result) + "</div>" +
        "<div class='sim-chart'><div class='sim-ctitle'>CVSS base-score distribution <span class='ct-sub'>(" + cv.nFindings.toLocaleString() + " generated vulns \u00B7 CVSS-B)</span></div>" + chartCvssBase(result) + "</div>" +
        "<div class='sim-chart'><div class='sim-ctitle'>Scalability <span class='ct-sub'>(mean rating vs ECU count, 1\u2013100)</span></div>" + chartScalability(scalabilitySweep(result.params)) + "</div>" +
        "<div class='sim-chart'><div class='sim-ctitle'>Weight sensitivity <span class='ct-sub'>(R vs \u00B120% weight change)</span></div>" + chartSensitivity(VRA.vehicle.sensitivity()) + "</div>" +
        "<div class='sim-chart'><div class='sim-ctitle'>Weight distribution <span class='ct-sub'>(Table H.8 weight w per component)</span></div>" + chartWeightHistogram(result) + "</div>" +
        "<div class='sim-chart'><div class='sim-ctitle'>Populated Table H.8 <span class='ct-sub'>(impact \u00D7 feasibility \u2192 component counts)</span></div>" + chartH8Matrix(result) + "</div>" +
      "</div>" +
      "<div class='sim-stars'><div class='sim-ctitle'>Star distribution</div>" + renderStars(s) + "</div>" +
      renderCaseCoverage(result);
  }
  function stat(k, v) { return "<div class='sc'><div class='sck'>" + k + "</div><div class='scv'>" + v + "</div></div>"; }

  function renderVnV() {
    var groups = verify(), total = 0, passed = 0;
    groups.forEach(function (g) { g.cases.forEach(function (c) { total++; if (c.pass) passed++; }); });
    var all = passed === total;
    var html = "<div class='vnv-head'><span class='vnv-badge " + (all ? "ok" : "fail") + "'>" +
      (all ? "V&V PASS" : "V&V FAIL") + "</span><span class='vnv-count'>" + passed + " / " + total + " rule checks pass</span></div>";
    groups.forEach(function (g) {
      var gp = g.cases.filter(function (c) { return c.pass; }).length;
      html += "<div class='vnv-group'><div class='vnv-gh'><b>" + esc(g.name) + "</b><span class='vnv-ref'>" + esc(g.ref) +
        "</span><span class='vnv-gcount " + (gp === g.cases.length ? "ok" : "fail") + "'>" + gp + "/" + g.cases.length + "</span></div><table class='vv'><tbody>";
      g.cases.forEach(function (c) {
        html += "<tr class='" + (c.pass ? "p" : "f") + "'><td class='vmark'>" + (c.pass ? "\u2713" : "\u2717") +
          "</td><td>" + esc(c.desc) + "</td><td class='vexp'>= " + esc(c.expected) + (c.pass ? "" : " \u00B7 got " + esc(c.got)) + "</td></tr>";
      });
      html += "</tbody></table></div>";
    });
    return html;
  }

  /* ===========================================================================
   * 12. CONTROLS + INIT
   * =========================================================================*/
  var lastResult = null;

  function featuresPanelHTML() {
    var sf = SIM().securityFeatures, rows = "";
    sf.catalogue.forEach(function (f) {
      if (f.options) {
        var opts = "<option value=''>none</option>" + f.options.map(function (o) {
          return "<option value='" + o.id + "'>" + esc(o.label) + " (\u2212" + o.weight.toFixed(2) + ")</option>";
        }).join("");
        rows += "<div class='sf-row'><label>" + esc(f.label) + "</label><select class='sf-group' data-g='" + f.id + "'>" + opts + "</select></div>";
      } else {
        rows += "<div class='sf-row'><label><input type='checkbox' class='sf-single' value='" + f.id + "'> " +
          esc(f.label) + " <span class='sf-w'>(\u2212" + f.weight.toFixed(2) + ")</span></label></div>";
      }
    });
    return "<details class='sf-panel' id='sf-panel'><summary>Security features \u2192 vulnerability probability " +
      "<span class='sf-derived' id='sf-derived'></span></summary>" +
      "<div class='sf-note'>Ported catalogue; weights are illustrative assumptions pending industry calibration. " +
      "Base 1.00, floor 0.05; grouped features are mutually exclusive. Used only when the mode above is set to \u201Cfrom features\u201D.</div>" +
      "<div class='sf-grid'>" + rows + "</div></details>";
  }

  function selectedFeatureIds() {
    var ids = [];
    document.querySelectorAll("#sf-panel .sf-single:checked").forEach(function (cb) { ids.push(cb.value); });
    document.querySelectorAll("#sf-panel .sf-group").forEach(function (sel) { if (sel.value) ids.push(sel.value); });
    return ids;
  }

  function refreshDerived() {
    var el = document.getElementById("sf-derived");
    if (el) el.textContent = "derived p = " + vulnProbFromFeatures(selectedFeatureIds()).toFixed(2);
    var mode = document.getElementById("sim-vpmode");
    var vp = document.getElementById("sim-vp");
    if (mode && vp) {
      if (mode.value === "features") { vp.value = Math.round(100 * vulnProbFromFeatures(selectedFeatureIds())); vp.disabled = true; }
      else if (mode.value === "featuresRandom") { vp.value = ""; vp.placeholder = "per vehicle"; vp.disabled = true; }
      else { vp.disabled = false; if (vp.value === "") vp.value = Math.round(100 * SIM().vulnProbability); }
    }
  }

  function readControls() {
    function num(id, dflt) { var el = document.getElementById(id); var v = el ? parseFloat(el.value) : NaN; return isNaN(v) ? dflt : v; }
    var p = SIM();
    var modeEl = document.getElementById("sim-vpmode");
    var mode = modeEl ? modeEl.value : p.vulnProbMode;
    var dist = readDistributions();
    return {
      vehicles: Math.max(1, Math.round(num("sim-vehicles", p.vehicles))),
      ecuCount: Math.max(0, Math.min(100, Math.round(num("sim-ecus", p.ecuCount)))),
      vulnProbMode: mode,
      securitySelection: selectedFeatureIds(),
      /* Manual probability may legitimately be 0 (the clean-fleet proof case:
       * 0% vulnerabilities MUST yield exactly 5 stars for every vehicle).
       * The 0.05 floor applies only to the features-derived modes, where it
       * encodes "no real system is fully secure". */
      vulnProbability: Math.max(0, Math.min(1, num("sim-vp", p.vulnProbability * 100) / 100)),
      vulnRange: [num("sim-vmin", p.vulnRange[0]), num("sim-vmax", p.vulnRange[1])],   // normalised in merge()
      piaProbability: Math.max(0, Math.min(1, num("sim-pia", p.piaProbability * 100) / 100)),
      seed: Math.round(num("sim-seed", p.seed)),
      domainProbability: dist.domainProbability,
      asilByDomain: dist.asilByDomain,
      netInteractionByDomain: dist.netInteractionByDomain
    };
  }

  /* Check the raw inputs against the model's rules and explain any that are not
   * allowed, together with the adaptation the run will apply. Nothing is silently
   * changed: the user sees what was adjusted and why. */
  function validateControls() {
    var alerts = [];
    function val(id) { var el = document.getElementById(id); return el ? parseFloat(el.value) : NaN; }
    var modeEl = document.getElementById("sim-vpmode");
    var manual = !modeEl || modeEl.value === "manual";
    var vp = val("sim-vp");
    if (manual && !isNaN(vp) && vp > 0 && vp < 5) {
      alerts.push({ what: "A vulnerability probability of " + vp + "% is not allowed.",
        why: "It has to be 0% (a perfect fleet, every component scores 5.00) or 5% and up. We can never claim under 5% uncertainty once a vulnerability is possible, so 1% to 4% do not exist.",
        fix: "Raised to 5% for this run." });
    }
    var vmax = val("sim-vmax"), vmin = val("sim-vmin");
    if (!isNaN(vmax) && vmax >= 7) {
      alerts.push({ what: "A maximum CVSS of " + vmax.toFixed(1) + " is not allowed.",
        why: "A CVSS of 7 or higher is a CRITICAL risk. Critical components are escalated and block approval rather than being scored, so the generator keeps findings below 7.",
        fix: "Capped at 6.9 for this run." });
    }
    if (!isNaN(vmin) && vmin >= 7) {
      alerts.push({ what: "A minimum CVSS of " + vmin.toFixed(1) + " is not allowed.",
        why: "A CVSS of 7 or higher is a CRITICAL risk, handled separately from the numeric score.",
        fix: "Capped at 6.9 for this run." });
    }
    return alerts;
  }
  function renderAlerts(alerts) {
    if (!alerts.length) return "";
    return "<div class='sim-alerts'>" + alerts.map(function (a) {
      return "<div class='sim-alert'><span class='sim-alert-i'>!</span><div><b>" + esc(a.what) + "</b> " + esc(a.why) +
        " <span class='sim-alert-fix'>\u2192 " + esc(a.fix) + "</span></div></div>";
    }).join("") + "</div>";
  }

  function doRun() {
    var host = document.getElementById("sim-output");
    var alertsHtml = renderAlerts(validateControls());
    if (host) host.innerHTML = "<div class='sim-running'>Generating fleet\u2026</div>";
    setTimeout(function () {
      lastResult = run(readControls());
      if (host) host.innerHTML = alertsHtml + renderResult(lastResult);
      var expC = document.getElementById("sim-export-comp");
      if (expC) expC.disabled = !lastResult.components;
    }, 10);
  }

  /* ---- advanced distributions panel: domain mix, ASIL & interaction per domain ---- */
  function distInput(id, val) {
    return "<input class='dist-in' id='" + id + "' type='number' step='any' min='0' value='" + val + "'>";
  }
  function secBtns(section) {
    return "<span class='dist-btns'>" +
      "<button type='button' class='dist-b' data-fill='" + section + "' data-mode='equal'>Equal</button>" +
      "<button type='button' class='dist-b' data-fill='" + section + "' data-mode='random'>Random</button></span>";
  }
  function distributionsPanelHTML() {
    var p = SIM(), domains = CFG().domains.map(function (d) { return d.id; });
    var ASIL = ["QM", "A", "B", "C", "D"], NET = ["Con", "E-E", "E-D", "E-C"];
    var dmix = domains.map(function (d) {
      return "<div class='dist-cell'><label>" + d + "</label>" + distInput("dp-" + d, p.domainProbability[d] || 0) + "</div>";
    }).join("");
    function tableFor(prefix, cols, get) {
      var head = "<tr><th>Domain</th>" + cols.map(function (c) { return "<th>" + c + "</th>"; }).join("") + "<th>\u03A3</th></tr>";
      var rows = domains.map(function (d) {
        var row = get(d);
        return "<tr><td class='dn'>" + d + "</td>" + cols.map(function (c, k) {
          return "<td>" + distInput(prefix + "-" + d + "-" + k, row[k] || 0) + "</td>";
        }).join("") + "<td class='dist-sum' data-sumrow='" + prefix + "-" + d + "' data-sumn='" + cols.length + "'>1.00</td></tr>";
      }).join("");
      return "<table class='dist-tab'>" + head + rows + "</table>";
    }
    return "<details class='sf-panel' id='dist-panel'><summary>Distributions (advanced): domain mix, ASIL per domain, interaction per domain</summary>" +
      "<div class='sf-note'>Each row is a set of <b>shares that sum to 1 (100%)</b>. For example, five equal domains are 0.20 each. The live \u03A3 shows the row total (green at 1.00). <b>Equal</b> = equal shares, <b>Random</b> = random shares (both sum to 1), <b>Normalise</b> rescales the entered values to sum to 1. Presets skew the model from defensive to aggressive across the architecture's own domains. A row left all-zero falls back to its paper default.</div>" +
      "<div class='dist-block'><div class='dist-title'>Domain mix (which domains the ECUs belong to)<span class='dist-sum' data-sum='domain' data-sumn='" + domains.length + "'>1.00</span>" + secBtns("domain") + "</div><div class='dist-row'>" + dmix + "</div></div>" +
      "<div class='dist-block'><div class='dist-title'>ASIL distribution per domain, impact axis (ISO 26262)" + secBtns("asil") + "</div>" + tableFor("asil", ASIL, function (d) { return p.asilByDomain[d] || [1, 0, 0, 0, 0]; }) + "</div>" +
      "<div class='dist-block'><div class='dist-title'>Network-interaction per domain, feasibility shift (Con +0, E-E +0, E-D +1, E-C +2)" + secBtns("net") + "</div>" + tableFor("net", NET, function (d) { return p.netInteractionByDomain[d] || [1, 0, 0, 0]; }) + "</div>" +
      "<div class='dist-presets'><span class='dp-lbl'>Model-behaviour presets:</span>" +
        "<button type='button' class='dist-b preset' data-preset='defensive'>Defensive</button>" +
        "<button type='button' class='dist-b preset' data-preset='intermediate'>Intermediate</button>" +
        "<button type='button' class='dist-b preset' data-preset='aggressive'>Aggressive</button>" +
        "<button type='button' id='dist-reset' class='dist-b'>Reset to paper</button></div>" +
      "</details>";
  }

  /** Read the advanced distributions (falls back to config defaults per cell). */
  function readDistributions() {
    var p = SIM(), domains = CFG().domains.map(function (d) { return d.id; });
    function n(id, def) { var el = document.getElementById(id); if (!el) return def; var v = parseFloat(el.value); return isNaN(v) ? def : Math.max(0, v); }
    function rowOrDefault(vals, def) { return vals.reduce(function (a, b) { return a + b; }, 0) > 0 ? vals : def.slice(); }
    var dp = {}, asil = {}, net = {};
    domains.forEach(function (d) {
      dp[d] = n("dp-" + d, p.domainProbability[d] || 0);
      var ar = p.asilByDomain[d] || [1, 0, 0, 0, 0];
      asil[d] = rowOrDefault([0, 1, 2, 3, 4].map(function (k) { return n("asil-" + d + "-" + k, ar[k] || 0); }), ar);
      var nr = p.netInteractionByDomain[d] || [1, 0, 0, 0];
      net[d] = rowOrDefault([0, 1, 2, 3].map(function (k) { return n("net-" + d + "-" + k, nr[k] || 0); }), nr);
    });
    if (domains.reduce(function (a, d) { return a + dp[d]; }, 0) <= 0) domains.forEach(function (d) { dp[d] = p.domainProbability[d] || 0; });
    return { domainProbability: dp, asilByDomain: asil, netInteractionByDomain: net };
  }
  /* "Reset to paper" — restore the full paper "typical vehicle" configuration:
   * the domain / ASIL / interaction distributions AND the main controls
   * (vehicles, ECU count, vulnerability probability and range, PIA, seed), all
   * read from the single-source defaults so the paper scenario is reproduced
   * in one click. */
  function resetDistributions() {
    var p = SIM(), domains = CFG().domains.map(function (d) { return d.id; });
    function set(id, v) { var el = document.getElementById(id); if (el) el.value = v; }
    domains.forEach(function (d) {
      set("dp-" + d, p.domainProbability[d] || 0);
      (p.asilByDomain[d] || []).forEach(function (v, k) { set("asil-" + d + "-" + k, v); });
      (p.netInteractionByDomain[d] || []).forEach(function (v, k) { set("net-" + d + "-" + k, v); });
    });
    set("sim-vehicles", p.vehicles);
    set("sim-ecus", p.ecuCount);
    set("sim-vp", Math.round(p.vulnProbability * 100));
    set("sim-vmin", p.vulnRange[0]);
    set("sim-vmax", p.vulnRange[1]);
    set("sim-pia", Math.round(p.piaProbability * 100));
    set("sim-seed", p.seed);
    var mode = document.getElementById("sim-vpmode"); if (mode) mode.value = p.vulnProbMode;
    updateDistSums();
  }

  function distSet(id, v) { var el = document.getElementById(id); if (el) el.value = v; }
  /* Rescale a set of shares to sum to exactly 1.00 (2 dp), absorbing the rounding
   * residual into the largest entry. All-zero input → equal shares. */
  function normaliseVals(vals) {
    var s = vals.reduce(function (a, b) { return a + b; }, 0);
    if (s <= 0) { var eq = Math.round(100 / vals.length) / 100; return vals.map(function () { return eq; }); }
    var out = vals.map(function (v) { return Math.round(v / s * 100) / 100; });
    var resid = Math.round((1 - out.reduce(function (a, b) { return a + b; }, 0)) * 100) / 100;
    var mi = 0; for (var i = 1; i < out.length; i++) if (out[i] > out[mi]) mi = i;
    out[mi] = Math.round((out[mi] + resid) * 100) / 100;
    return out;
  }
  /* Fill a row of inputs: "equal" = 1/n each; "random" = random shares that
   * sum to 1. Both leave the row summing to 100%. */
  function fillRow(ids, mode) {
    if (mode === "equal") {
      var eq = Math.round(100 / ids.length) / 100;
      ids.forEach(function (id) { distSet(id, eq); });
    } else {
      var vals = ids.map(function () { return 0.5 + Math.random(); });
      normaliseVals(vals).forEach(function (v, i) { distSet(ids[i], v); });
    }
  }
  /* Auto-fill a whole section. Every mode leaves each row summing to 1 (100%). */
  function distFill(section, mode) {
    var domains = CFG().domains.map(function (d) { return d.id; });
    if (section === "domain") { fillRow(domains.map(function (d) { return "dp-" + d; }), mode); }
    else {
      var n = section === "asil" ? 5 : 4;
      domains.forEach(function (d) {
        var ids = []; for (var k = 0; k < n; k++) ids.push(section + "-" + d + "-" + k);
        fillRow(ids, mode);
      });
    }
    updateDistSums();
  }
  /* Model-behaviour presets over the architecture's domains, each row normalised
   * to sum to 1. Defensive skews safety low + interaction contained (mild
   * ratings); Aggressive does the opposite (harsh ratings); Intermediate is
   * balanced. Domain mix → equal shares. */
  var DIST_PRESETS = {
    defensive:    { asil: [4, 3, 2, 1, 0.5], net: [4, 3, 1, 0.5] },
    intermediate: { asil: [2, 2, 2, 1, 1],   net: [2, 2, 1, 1] },
    aggressive:   { asil: [0.5, 1, 2, 3, 4], net: [0.5, 1, 3, 4] }
  };
  function distPreset(mode) {
    var pr = DIST_PRESETS[mode]; if (!pr) return;
    var domains = CFG().domains.map(function (d) { return d.id; });
    var asilN = normaliseVals(pr.asil.slice()), netN = normaliseVals(pr.net.slice());
    var dEq = Math.round(100 / domains.length) / 100;
    domains.forEach(function (d) {
      distSet("dp-" + d, dEq);
      asilN.forEach(function (v, k) { distSet("asil-" + d + "-" + k, v); });
      netN.forEach(function (v, k) { distSet("net-" + d + "-" + k, v); });
    });
    updateDistSums();
  }
  /* Live Σ readout: recompute each row total, mark green when it reaches 1.00. */
  function updateDistSums() {
    var domains = CFG().domains.map(function (d) { return d.id; });
    function rowSum(ids) { return ids.reduce(function (a, id) { var el = document.getElementById(id); return a + (el ? Math.max(0, parseFloat(el.value) || 0) : 0); }, 0); }
    function paint(el, s) { var r = Math.round(s * 100) / 100; el.textContent = r.toFixed(2); if (r >= 0.995 && r <= 1.005) el.className = "dist-sum ok"; else el.className = "dist-sum"; }
    var dEl = document.querySelector("[data-sum='domain']");
    if (dEl) paint(dEl, rowSum(domains.map(function (d) { return "dp-" + d; })));
    Array.prototype.forEach.call(document.querySelectorAll("[data-sumrow]"), function (cell) {
      var pfx = cell.getAttribute("data-sumrow"), n = parseInt(cell.getAttribute("data-sumn"), 10), ids = [];
      for (var k = 0; k < n; k++) ids.push(pfx + "-" + k);
      paint(cell, rowSum(ids));
    });
  }

  function controlsHTML() {
    var p = SIM();
    return "<div class='sim-controls'>" +
      ctl("sim-vehicles", "Vehicles", p.vehicles, "1", "") +
      ctl("sim-ecus", "ECUs / vehicle", p.ecuCount, "0", "100") +
      "<div class='sim-field'><label for='sim-vpmode'>Vuln. probability mode</label>" +
        "<select id='sim-vpmode'>" +
        "<option value='manual'>Manual %</option>" +
        "<option value='features'>From features (selected)</option>" +
        "<option value='featuresRandom'>From features (random / vehicle)</option>" +
        "</select></div>" +
      ctl("sim-vp", "Vuln. probability %", Math.round(p.vulnProbability * 100), "0", "100") +
      ctl("sim-vmin", "Min CVSS", p.vulnRange[0], "0", "6.9") +
      ctl("sim-vmax", "Max CVSS", p.vulnRange[1], "0", "6.9") +
      ctl("sim-pia", "PIA probability %", Math.round(p.piaProbability * 100), "0", "100") +
      ctl("sim-seed", "Seed", p.seed, "0", "") +
      "<div class='sim-presets'>" +
        "<button class='sim-preset' data-n='1000'>1000</button>" +
        "<button class='sim-preset' data-n='5000'>5000</button>" +
        "<button class='sim-preset' data-n='10000'>10000</button>" +
      "</div>" +
      "<div class='sim-actions'>" +
        "<button id='sim-run' class='sim-run'>Run simulation</button>" +
        "<button id='sim-export' class='sim-export'>CSV / vehicle</button>" +
        "<button id='sim-export-comp' class='sim-export'>CSV / component</button>" +
        "<button id='sim-export-charts' class='sim-export'>CSV / chart data</button>" +
      "</div></div>" +
      distributionsPanelHTML();
  }
  function ctl(id, label, val, min, max) {
    return "<div class='sim-field'><label for='" + id + "'>" + label + "</label>" +
      "<input id='" + id + "' type='number' value='" + val + "'" +
      (min !== "" ? " min='" + min + "'" : "") + (max !== "" ? " max='" + max + "'" : "") + " step='any'></div>";
  }

  function wire() {
    var runBtn = document.getElementById("sim-run");
    if (runBtn) runBtn.addEventListener("click", doRun);
    var exp = document.getElementById("sim-export");
    if (exp) exp.addEventListener("click", function () {
      if (!lastResult) { doRun(); return; }
      var ok = download("fleet_seed" + lastResult.params.seed + "_n" + lastResult.params.vehicles + ".csv", toCSV(lastResult));
      if (!ok) alert("CSV export needs a browser download context.");
    });
    var expC = document.getElementById("sim-export-comp");
    if (expC) expC.addEventListener("click", function () {
      if (!lastResult) { doRun(); return; }
      var csv = toComponentCSV(lastResult);
      if (!csv) { alert("Fleet exceeds " + SIM().maxComponentRecords.toLocaleString() + " components. Per-component records were not kept. Reduce the fleet size."); return; }
      var ok = download("components_seed" + lastResult.params.seed + "_n" + lastResult.params.vehicles + ".csv", csv);
      if (!ok) alert("CSV export needs a browser download context.");
    });
    var expCharts = document.getElementById("sim-export-charts");
    if (expCharts) expCharts.addEventListener("click", function () {
      if (!lastResult) { doRun(); return; }
      var ok = download("chartdata_seed" + lastResult.params.seed + "_n" + lastResult.params.vehicles + ".csv", toChartCSV(lastResult));
      if (!ok) alert("CSV export needs a browser download context.");
    });
    Array.prototype.forEach.call(document.querySelectorAll(".sim-preset"), function (b) {
      b.addEventListener("click", function () {
        var el = document.getElementById("sim-vehicles"); if (el) el.value = b.getAttribute("data-n"); doRun();
      });
    });
    var mode = document.getElementById("sim-vpmode");
    if (mode) mode.addEventListener("change", refreshDerived);
    var panel = document.getElementById("sf-panel");
    if (panel) panel.addEventListener("change", refreshDerived);
    var distReset = document.getElementById("dist-reset");
    if (distReset) distReset.addEventListener("click", resetDistributions);
    var distPanel = document.getElementById("dist-panel");
    if (distPanel) {
      distPanel.addEventListener("click", function (ev) {
        var t = ev.target;
        if (t && t.getAttribute && t.getAttribute("data-fill")) { ev.preventDefault(); distFill(t.getAttribute("data-fill"), t.getAttribute("data-mode")); }
        else if (t && t.getAttribute && t.getAttribute("data-preset")) { ev.preventDefault(); distPreset(t.getAttribute("data-preset")); }
      });
      distPanel.addEventListener("input", updateDistSums);
      updateDistSums();  // initialise the live Σ badges
    }
    refreshDerived();
  }

  VRA.simulation = {
    run: run, toCSV: toCSV, toComponentCSV: toComponentCSV, toChartCSV: toChartCSV, verify: verify,
    buildVulnPool: buildVulnPool, vulnProbFromFeatures: vulnProbFromFeatures,
    init: function () {
      if (!VRA.config || !VRA.vehicle) return;
      var app = document.getElementById("simulation-app");
      if (app) {
        app.innerHTML =
          "<div class='comp-note'>Generates synthetic vehicles from the distributions in <span class='mono'>config.js</span> (all editable below, including the domain mix and the per-domain ASIL and interaction distributions in the <b>Distributions (advanced)</b> panel) and runs each through the same star score, Table H.8 weight + \u03A3(s\u00B7w)/\u03A3(w) pipeline. " +
          "Vulnerabilities are drawn from the <b>exact set of achievable CVSS v3.1 base scores</b> inside [Min, Max]; the seed makes every run reproducible; export the data per vehicle or per component.</div>" +
          controlsHTML() + "<div id='sim-output'></div>" +
          "<div class='sf-after'><div class='sf-after-lead'>Optional security features view: see how much vulnerability probability each set of ECU protections implies. This does not change the run above unless you switch the probability mode to \u201cfeatures\u201d.</div>" +
          featuresPanelHTML() +
          "<div class='sim-observation'><span class='sim-obs-tag'>vuln note</span><span>Vulnerability probability is either <b>0%</b> (a perfect fleet, every component scores 5.00) or <b>5% and up</b>. Values from 1% to 4% are raised to 5%, since we can never claim under 5% uncertainty once a vulnerability is possible.</span></div>" +
          "</div>";
        wire();
        doRun();
      }
      var vnv = document.getElementById("simulation-vnv");
      if (vnv) vnv.innerHTML = renderVnV();
    }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", VRA.simulation.init);
  else VRA.simulation.init();
})();
