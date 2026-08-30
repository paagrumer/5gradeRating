/* =============================================================================
 * VRA — RATING LOGIC  (component + vehicle, in one file so the rules are easy to
 * assess). The reference car and the fleet simulation both run this exact code,
 * so the rules you read here are the rules the tool uses. Every number comes from
 * config.js. Nothing is hidden.
 *
 * THE TWO STEPS
 *   PART A gives each component its own star score s, from 0 to 5.
 *   PART B combines those into one vehicle rating R, from 0 to 5.
 *
 * PART A — COMPONENT STAR SCORE  s   (one ECU, CSCS'23 Algorithm 1)
 *   1. Take the component's confirmed vulnerabilities (CVEs, each with a CVSS score).
 *   2. Group them by category and keep only the worst CVSS in each category, so
 *      many minor vulnerabilities cannot mask one serious one.
 *   3. Sort the categories worst-first and keep the top three: C0, C1, C2.
 *   4. Combine them, giving the worst the most weight:
 *        one category         X = C0
 *        two categories       X = 0.6*C0 + 0.4*C1
 *        three categories     X = 0.6*C0 + 0.3*C1 + 0.1*C2
 *        any CVSS in [5.3, 7)  worst-case: X = C0  (just the single worst vulnerability)
 *        any CVSS >= 7         CRITICAL: no score, the component is escalated
 *   5. Turn X into a score:  s = -0.725*X + 5, kept inside [0, 5].
 *        No vulnerabilities at all -> s = 5.00 (the only way to score a perfect 5).
 *        Any vulnerability at all -> s is capped at 4.75, because we can never call
 *                          something more than 95% secure once a vulnerability exists.
 *      Example: C = [5, 4, 3] -> three categories -> X = 4.5 -> s = 1.74.
 *
 * PART B — VEHICLE RATING  R
 *   Each component gets a weight w (1 to 5) from Table H.8, read as
 *   w = H.8[impact][feasibility]:
 *     impact      comes from the component's ASIL (how much it matters for
 *                 safety). A privacy impact assessment bumps it up one level.
 *     feasibility comes from the CVSS exploitability E = 8.22*AV*AC*PR*UI of the
 *                 same worst categories, combined with the SAME weights used in
 *                 PART A, then read off Table G.8. Talking to more of the car
 *                 nudges it up. A clean component sits at the lowest level.
 *   The rating is the weighted mean:  R = sum(s*w) / sum(w).
 *     All components clean -> R = 5.00. A vulnerability pulls R down in proportion to how
 *     much that component matters. A CRITICAL component is pulled out and
 *     escalated, not hidden in the average.
 *
 * STANDARDS: CSCS'23 Algorithm 1 (star score); ISO/SAE 21434 Annex G (feasibility,
 *   Table G.8) and Annex H (weight, Tables H.8/H.9/H.10); ISO 26262-3 (ASIL to
 *   impact); UN ECE R155 §7.2.2.2 (R is the risk output, CRITICAL blocks approval);
 *   CVSS v3.1 (FIRST) for the base scores and E.
 *
 * API: VRA.component.starScore(findings) / rate / verify / init
 *      VRA.vehicle.exploitability / feasibility / impact / weight / rate /
 *                 rateSet / rating / sensitivity / verify / init
 * ========================================================================== */

/* ===========================================================================
 * ###########################################################################
 * ##  PART A — COMPONENT LEVEL  (star score s · Algorithm 1)                     ##
 * ###########################################################################
 * =========================================================================*/
(function () {
  "use strict";
  var VRA = (window.VRA = window.VRA || {});
  function CFG() { return VRA.config; }
  function SC()  { return VRA.config.scoring; }
  function round2(x) { return Math.round((x + 1e-9) * 100) / 100; }

  /* ===========================================================================
   * 1. STAR-SCORE ENGINE  (Algorithm 1)
   * =========================================================================*/

  /**
   * Compute the component star score from its findings.
   *
   * Anti-dilution: grouping by category and keeping only the worst CVSS per
   * category (then capping at 3) prevents many findings in one area from
   * padding or dragging the score.  A High/Critical finding (≥ 7) is never
   * diluted — it raises a critical security risk instead of a number.
   *
   * @param {Array<{cvss:number, category?:string, cve?:string}>} findings
   * @returns {object} star score result
   */
  function starScore(findings) {
    var st = SC().starScore;

    /* No confirmed finding → full star score. */
    if (!findings || !findings.length) {
      return { critical: false, s: st.clean, X: 0, branch: "no finding", case: 0, terms: [], categories: [], kept: [] };
    }

    /* CA — worst CVSS per category. */
    var byCat = {};
    findings.forEach(function (f) {
      var cat = f.category || "Other";
      if (!(cat in byCat) || f.cvss > byCat[cat].cvss) byCat[cat] = { cat: cat, cvss: f.cvss, cve: f.cve, f: f };
    });
    var CA = Object.keys(byCat).map(function (k) { return byCat[k]; });

    /* Sort descending, keep 3 worst, remove zeros. */
    var sorted = CA.slice().sort(function (a, b) { return b.cvss - a.cvss; });
    var C = sorted.slice(0, st.maxCategories).filter(function (x) { return x.cvss > 0; });
    var n = C.length;

    /* Branch (C): any category ≥ highThreshold → critical security risk. */
    if (C.some(function (x) { return x.cvss >= st.highThreshold; })) {
      return { critical: true, error: st.criticalError, branch: "critical (\u2265" + st.highThreshold + ")",
               categories: sorted, kept: C, n: n };
    }

    var X, branch, kase, terms;
    if (C.every(function (x) { return x.cvss < st.lowThreshold; })) {
      /* Branch (A): all < 5.3 → weighted cases. */
      kase = n;
      if (n === 0) { X = 0; terms = []; }
      else {
        var w = st.caseWeights[String(n)];
        terms = C.map(function (x, i) { return { w: w[i], v: x.cvss, cat: x.cat }; });
        X = terms.reduce(function (a, t) { return a + t.w * t.v; }, 0);
      }
      branch = "all < " + st.lowThreshold + " \u2192 case " + n;
    } else {
      /* Branch (B): some in [5.3, 7) → worst-case (single worst vuln used). */
      kase = "worst";
      terms = [{ w: 1, v: C[0].cvss, cat: C[0].cat }];
      X = C[0].cvss;
      branch = "\u2265 " + st.lowThreshold + " \u2192 worst-case (single vuln used)";
    }

    /* Any confirmed vulnerability means we cannot certify more than 95% secure,
     * so cap the star score at max·(1−residualFraction) = 4.75. Only a clean component
     * (handled above) can reach 5.00. */
    var s = Math.max(st.min, Math.min(st.max, st.slope * X + st.intercept));
    var vulnCap = st.max * (1 - st.residualFraction);
    if (s > vulnCap) s = vulnCap;
    return { critical: false, s: s, X: X, branch: branch, case: kase, terms: terms, categories: sorted, kept: C, n: n };
  }

  /** Full component result (star score only — weight and aggregation are in vehicle.js). */
  function rate(ecu) {
    var r = starScore(ecu.findings);
    return {
      ecu: ecu,
      critical: r.critical,
      scoreRaw: r.critical ? null : r.s,
      starScore: r.critical ? null : round2(r.s),
      X: r.critical ? null : r.X,
      branch: r.branch, case: r.case, terms: r.terms, categories: r.categories, kept: r.kept,
      findings: (ecu.findings || []).slice().sort(function (a, b) { return b.cvss - a.cvss; }),
      result: r
    };
  }

  /* ===========================================================================
   * 2. VERIFICATION & VALIDATION
   * =========================================================================*/
  function F(pairs) { return (pairs || []).map(function (p) { return { cvss: p[0], category: p[1] }; }); }
  function sVal(pairs) { var r = starScore(F(pairs)); return r.critical ? "CRITICAL" : round2(r.s).toFixed(2); }
  function check(desc, expected, got) {
    return { desc: desc, expected: String(expected), got: String(got), pass: String(expected) === String(got) };
  }

  function verify() {
    var groups = [];

    /* (a) Category grouping — worst CVSS per category, anti-dilution. */
    groups.push({
      name: "Category grouping  (worst CVSS per category)", ref: "Algorithm 1 \u00B7 CA = {max(V\u1D62)}",
      cases: [
        check("same category collapses [4.4 SW, 2.4 SW] \u2192 one category", "1.81", sVal([[4.4, "Software"], [2.4, "Software"]])),
        check("different categories [4.4 SW, 2.4 N] \u2192 two categories",   "2.39", sVal([[4.4, "Software"], [2.4, "Networks"]])),
        check("4th category dropped (cap 3) \u2192 same as 3",                "1.74", sVal([[5, "Networks"], [4, "Software"], [3, "Diagnostics"], [2, "Cryptography"]])),
        check("zero-CVSS category removed",                                  "1.81", sVal([[4.4, "Software"], [0, "Networks"]]))
      ]
    });

    /* (b) Threshold branches — the three decision paths. */
    groups.push({
      name: "Threshold branches  (5.3 and 7.0)", ref: "Algorithm 1 \u00B7 if / else-if / else-if",
      cases: [
        check("all < 5.3 \u2192 weighted [4.0 N] \u2192 2.10",               "2.10", sVal([[4.0, "Networks"]])),
        check("[5.3, 7) \u2192 worst-case [5.9 N] \u2192 0.72",              "0.72", sVal([[5.9, "Networks"]])),
        check("[5.3, 7) worst-case ignores 2nd [6.8 N, 6.5 D] \u2192 0.07",  "0.07", sVal([[6.8, "Networks"], [6.5, "Diagnostics"]])),
        check("\u2265 7 \u2192 critical error [7.0 SW]",                      "CRITICAL", sVal([[7.0, "Software"]])),
        check("\u2265 7 anywhere \u2192 critical [4.0 S, 7.5 N]",             "CRITICAL", sVal([[4.0, "Software"], [7.5, "Networks"]]))
      ]
    });

    /* (c) Weighted cases — positional weights for all-below-5.3 branch. */
    groups.push({
      name: "Weighted cases  (all categories < 5.3)", ref: "Algorithm 1 \u00B7 case 1/2/3, \u03C9 weights",
      cases: [
        check("case 0 \u00B7 no finding \u2192 5.00",                         "5.00", sVal([])),
        check("case 1 \u00B7 [4.4 N] \u2192 1.0\u00B74.4 \u2192 1.81",        "1.81", sVal([[4.4, "Networks"]])),
        check("case 2 \u00B7 [4.4 N, 2.4 S] \u2192 0.6\u00B74.4+0.4\u00B72.4 \u2192 2.39", "2.39", sVal([[4.4, "Networks"], [2.4, "Software"]])),
        check("case 3 \u00B7 [5 N, 4 S, 3 D] \u2192 0.6\u00B75+0.3\u00B74+0.1\u00B73 \u2192 1.74", "1.74", sVal([[5, "Networks"], [4, "Software"], [3, "Diagnostics"]]))
      ]
    });

    /* (c2) Residual insecurity — a 5.00 means zero vulnerabilities, and anything
     * vulnerable is capped at 4.75 because we cannot certify 100% security. */
    groups.push({
      name: "Residual insecurity  (5.00 only when clean)", ref: "5% floor \u00B7 cap = 5\u00B7(1\u22120.05) = 4.75",
      cases: [
        check("no finding \u2192 exactly 5.00", "5.00", sVal([])),
        check("tiny vuln [0.1 N] would be 4.93, capped \u2192 4.75", "4.75", sVal([[0.1, "Networks"]])),
        check("a vulnerable star score never exceeds 4.75", "true",
          String([[0.1, "Networks"], [0.5, "Software"], [1.0, "Diagnostics"]].every(function (f) { return Number(sVal([f])) <= 4.75; }))),
        check("normal vuln below the cap is untouched [1.0 N] \u2192 4.28", "4.28", sVal([[1.0, "Networks"]]))
      ]
    });

    /* (c3) Face validity — the rating ranks cars the way a person would expect. */
    var clean = { id: "x", name: "Clean", asil: "D", domain: "ADAS", netInteraction: "Con", findings: [] };
    var oneBug = { id: "x", name: "One", asil: "D", domain: "ADAS", netInteraction: "Con", findings: [{ cvss: 4.0, category: "Networks", av: "N", ac: "L", pr: "N", ui: "N" }] };
    var worse = { id: "x", name: "Worse", asil: "D", domain: "ADAS", netInteraction: "Con", findings: [{ cvss: 6.5, category: "Networks", av: "N", ac: "L", pr: "N", ui: "N" }] };
    groups.push({
      name: "Face validity  (does it rank like a human would?)", ref: "sanity checks on ordering",
      cases: [
        check("a clean component scores 5.00", "5.00", starScore(clean.findings).s.toFixed(2)),
        check("one vulnerability drops it below 5", "true", String(starScore(oneBug.findings).s < 5)),
        check("a worse vulnerability scores lower than a milder one", "true", String(starScore(worse.findings).s < starScore(oneBug.findings).s)),
        check("worst stays within [0, 4.75]", "true", String(starScore(worse.findings).s >= 0 && starScore(worse.findings).s <= 4.75))
      ]
    });

    /* (d) Algorithm 2 reproduction — the paper's worked example. */
    groups.push({
      name: "Algorithm 2 reproduction  (paper\u2019s worked example)", ref: "CSCS '23 \u00B7 Algorithm 2",
      cases: [
        check("C = [5, 4, 3] \u2192 X = 4.5 \u2192 s = 1.74", "1.74", sVal([[5, "Networks"], [4, "Software"], [3, "Diagnostics"]]))
      ]
    });

    /* (e) Reference components — the config roster's findings. */
    function refC(desc, pairs, expected) { return check(desc, expected, sVal(pairs)); }
    groups.push({
      name: "Reference components  (from config findings)", ref: "config.ecus category assignments",
      cases: [
        refC("Infotainment Head Unit [6.8 SW, 6.5 N] \u2192 worst-case", pairs_hu(), "0.07"),
        refC("Instrument Cluster [5.9 N] \u2192 worst-case",            [[5.9, "Networks"]], "0.72"),
        refC("Door Control [4.4 SW] \u2192 case 1",                     [[4.4, "Software"]], "1.81"),
        refC("Body Control [4.4 SW, 2.4 SW] same category \u2192 case 1", [[4.4, "Software"], [2.4, "Software"]], "1.81"),
        refC("clean component (no finding) \u2192 5.00",                [], "5.00")
      ]
    });

    return groups;
  }

  /** Read the head-unit findings from config so the test tracks the roster. */
  function pairs_hu() {
    var e = (CFG().ecus || []).filter(function (x) { return x.id === "hu"; })[0];
    return e ? e.findings.map(function (f) { return [f.cvss, f.category]; }) : [[6.8, "Software"], [6.5, "Networks"]];
  }

  /* ===========================================================================
   * 3. RENDERING
   * =========================================================================*/
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

  function renderVnV() {
    var groups = verify(), total = 0, passed = 0;
    groups.forEach(function (g) { g.cases.forEach(function (c) { total++; if (c.pass) passed++; }); });
    var allPass = passed === total;
    var html = "<div class='vnv-head'><span class='vnv-badge " + (allPass ? "ok" : "fail") + "'>" +
      (allPass ? "V&V PASS" : "V&V FAIL") + "</span><span class='vnv-count'>" + passed + " / " + total + " rule checks pass</span></div>";
    groups.forEach(function (g) {
      var gp = g.cases.filter(function (c) { return c.pass; }).length;
      html += "<div class='vnv-group'><div class='vnv-gh'><b>" + esc(g.name) + "</b><span class='vnv-ref'>" + esc(g.ref) +
        "</span><span class='vnv-gcount " + (gp === g.cases.length ? "ok" : "fail") + "'>" + gp + "/" + g.cases.length + "</span></div><table class='vv'><tbody>";
      g.cases.forEach(function (c) {
        html += "<tr class='" + (c.pass ? "p" : "f") + "'><td class='vmark'>" + (c.pass ? "\u2713" : "\u2717") +
          "</td><td>" + esc(c.desc) + "</td><td class='vexp'>expected " + esc(c.expected) + (c.pass ? "" : " \u00B7 got " + esc(c.got)) + "</td></tr>";
      });
      html += "</tbody></table></div>";
    });
    return html;
  }

  function catList(cats) {
    return cats.map(function (c) { return c.cvss.toFixed(1) + " (" + c.cat + ")"; }).join(", ") || "none";
  }

  function renderTable() {
    function caseInfo(r) {
      if (r.critical) return { label: "Critical", cls: "critical" };
      if (r.case === 0) return { label: "Clean", cls: "clean" };
      if (r.case === 1) return { label: "Case 1", cls: "case1" };
      if (r.case === 2) return { label: "Case 2", cls: "case2" };
      if (r.case === 3) return { label: "Case 3", cls: "case3" };
      return { label: "Worst-case (\u2265 5.3 \u00B7 single vuln used)", cls: "worst" };
    }
    var rows = CFG().ecus.map(function (ecu, i) {
      var r = rate(ecu);
      var f = r.findings.length
        ? r.findings.map(function (x) { return "<a class='mono cve-lnk' href='https://nvd.nist.gov/vuln/detail/" + esc(x.cve) + "' target='_blank' rel='noopener'>" + esc(x.cve) + "</a> <span class='dim'>" + x.cvss.toFixed(1) + "\u00B7" + (x.category || "?").slice(0, 4) + "</span>"; }).join("<br>")
        : "<span class='dim'>none</span>";
      var worst3 = r.kept && r.kept.length ? catList(r.kept) : "none";
      var info = caseInfo(r);
      var brCell = "<span class='branch b-" + info.cls + "'>" + info.label + "</span>";
      var scoreCell = r.critical
        ? "<span class='crit'>CRITICAL</span>"
        : "<span class='n " + (r.findings.length ? "" : "clean") + "'>" + r.starScore.toFixed(2) + "</span>";
      var xCell = r.critical ? "n/a" : (r.X != null ? r.X.toFixed(2) : "none");
      return "<tr data-i='" + i + "'>" +
        "<td>" + esc(ecu.name) + "</td>" +
        "<td class='dim mono'>" + esc(ecu.ref) + "</td>" +
        "<td class='dim'>" + ecu.domain + " \u00B7 " + ecu.zone + "</td>" +
        "<td class='cve'>" + f + "</td>" +
        "<td>" + worst3 + "</td>" +
        "<td>" + brCell + "</td>" +
        "<td class='n'>" + xCell + "</td>" +
        "<td class='n'>" + scoreCell + "</td></tr>";
    }).join("");
    return "<div class='comp-wrap'><table class='comp'><thead><tr>" +
      "<th>Component</th><th>Ref</th><th>Domain \u00B7 Zone</th><th>Identified CVE \u00B7 CVSS \u00B7 cat</th>" +
      "<th>3 worst categories</th><th>Branch</th><th class='n'>CVSS_C</th><th class='n'>Star score s</th></tr></thead><tbody>" +
      rows + "</tbody></table></div>";
  }

  function renderDerivation(ecu) {
    var r = rate(ecu), st = SC().starScore;
    var out = "<div class='dv-title'><b>" + esc(ecu.name) + "</b>: star score derivation (Algorithm 1)</div>";
    out += "<div class='dv-step'><span class='dv-k'>Findings</span>" +
      (r.findings.length ? r.findings.map(function (x) { return (x.cve ? x.cve + " " : "") + "CVSS " + x.cvss.toFixed(1) + " (" + (x.category || "?") + ")"; }).join("; ") : "none") + "</div>";
    out += "<div class='dv-step'><span class='dv-k'>Category decision</span>worst CVSS per category, sorted: " + esc(catList(r.categories)) +
      (r.categories.length > st.maxCategories ? "  \u2192 keep 3 worst" : "") + "</div>";

    if (r.critical) {
      out += "<div class='dv-step crit-step'><span class='dv-k'>Branch (C)</span>a category is \u2265 " + st.highThreshold +
        " (High/Critical) \u2192 <b>Error: \u201C" + esc(st.criticalError) + "\u201D</b>, so no numeric star score is issued.</div>";
    } else if (r.findings.length === 0) {
      out += "<div class='dv-step'><span class='dv-k'>Result</span>no confirmed finding \u2192 s = <b>5.00</b></div>";
    } else {
      var terms = r.terms.map(function (t) { return t.w.toFixed(2) + "\u00B7" + t.v.toFixed(1) + "(" + t.cat + ")"; }).join(" + ");
      out += "<div class='dv-step'><span class='dv-k'>Branch</span>" + esc(r.branch) + "</div>";
      out += "<div class='dv-step'><span class='dv-k'>Combine</span>CVSS_C = " + terms + " = <b>" + r.X.toFixed(2) + "</b></div>";
      out += "<div class='dv-step'><span class='dv-k'>Star score</span>s = \u22120.725\u00B7" + r.X.toFixed(2) + " + 5 = <b>" + r.starScore.toFixed(2) + "</b></div>";
      out += "<div class='dv-sub'>CVSS_C is the component's combined CVSS. It is the value the CSCS paper's Algorithm 1 calls X.</div>";
    }
    out += "<div class='dv-note'>This gives the component star score only. The next phase, in <b>Vehicle Stars</b>, adds the Table H.8 weight and combines the components into the vehicle rating.</div>";
    return out;
  }

  function wireRows() {
    var host = document.getElementById("component-app");
    if (!host) return;
    var detail = host.querySelector("#comp-deriv");
    host.querySelectorAll("table.comp tbody tr").forEach(function (tr) {
      tr.addEventListener("click", function () {
        host.querySelectorAll("table.comp tbody tr").forEach(function (t) { t.classList.remove("sel"); });
        tr.classList.add("sel");
        if (detail) detail.innerHTML = renderDerivation(CFG().ecus[+tr.getAttribute("data-i")]);
      });
    });
  }

  /* ===========================================================================
   * 4. INIT
   * =========================================================================*/
  VRA.component = {
    starScore: starScore, rate: rate, verify: verify, explain: renderDerivation,
    init: function () {
      if (!VRA.config) return;
      var app = document.getElementById("component-app");
      if (app) {
        app.innerHTML =
          "<div class='comp-note'>Each component\u2019s <b>star score</b> is computed live from its findings via CSCS Algorithm 1 " +
          "(<span class='mono'>config.js</span>). This step computes the component star score. The Table H.8 weight and the vehicle rating come next, in <b>Vehicle Stars</b>. Click a row for the full derivation.</div>" +
          renderTable() + "<div id='comp-deriv' class='deriv'></div>";
        wireRows();
        var first = app.querySelector("table.comp tbody tr");
        if (first) first.click();
      }
      var vnv = document.getElementById("component-vnv");
      if (vnv) vnv.innerHTML = renderVnV();
    }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", VRA.component.init);
  else VRA.component.init();
})();

/* ===========================================================================
 * ###########################################################################
 * ##  PART B — VEHICLE LEVEL  (weight w = Table H.8 · rating R = Σsw/Σw)    ##
 * ###########################################################################
 * =========================================================================*/
(function () {
  "use strict";
  var VRA = (window.VRA = window.VRA || {});
  function CFG() { return VRA.config; }
  function SC()  { return VRA.config.scoring; }
  function round(x, n) { var f = Math.pow(10, n == null ? 2 : n); return Math.round((x + 1e-9) * f) / f; }

  /* ===========================================================================
   * 1. FEASIBILITY  (CVSS exploitability -> Table G.8 -> interaction shift)
   * ------------------------------------------------------------------------- */

  /** E = k * AV * AC * PR * UI for one finding (ISO/SAE 21434 Annex G.3). */
  function exploitability(f) {
    var c = SC().cvss;
    var av = c.AV[f.av], ac = c.AC[f.ac], pr = c.PR[f.pr], ui = c.UI[f.ui];
    if (av == null || ac == null || pr == null || ui == null) return null; // missing vector
    return c.k * av * ac * pr * ui;
  }

  /** Map an exploitability value to a Table G.8 feasibility band. */
  function bandOf(e) {
    var bands = SC().feasibilityBands, chosen = bands[0];
    for (var i = 0; i < bands.length; i++) if (e >= bands[i].minE) chosen = bands[i];
    return chosen; // { label, minE, col }
  }

  /** Component attack-feasibility rating (col index + label) after the shift. */
  /* Feasibility uses the SAME dilution as the star score: the exploitability E of the
   * three worst categories' representative findings is combined with the exact
   * case weights the star score applies to their CVSS base scores (case 1 → E0;
   * case 2 → 0.6·E0 + 0.4·E1; case 3 → 0.6·E0 + 0.3·E1 + 0.1·E2; worst-case →
   * E0). So both Table H.8 axes react to a component's findings in the same way.
   * A clean component → lowest band; then the network-interaction shift. */
  function feasibility(ecu) {
    var sc = SC(), st = VRA.component.starScore(ecu.findings || []);
    var kept = st.kept || [];
    var Es = kept.map(function (c) { return exploitability(c.f); }).filter(function (e) { return e != null; });
    var w = (st.case === "worst" || st.critical) ? [1] : (sc.starScore.caseWeights[String(Es.length)] || [1]);
    var Ew = Es.length ? Es.reduce(function (a, e, i) { return a + (w[i] || 0) * e; }, 0) : null;
    var base = Ew == null ? bandFromLabel(sc.cleanBaseFeasibility) : bandOf(Ew);
    var shift = sc.networkInteractionShift[ecu.netInteraction] || 0;
    var maxCol = sc.feasibilityLevels.length - 1;
    var col = Math.min(base.col + shift, maxCol);
    return {
      label: sc.feasibilityLevels[col], col: col,
      baseLabel: base.label, baseCol: base.col, shift: shift,
      E: Ew, Es: Es, weights: w, clean: Es.length === 0, capped: base.col + shift > maxCol
    };
  }
  function bandFromLabel(label) {
    var b = SC().feasibilityBands.filter(function (x) { return x.label === label; })[0];
    return b || SC().feasibilityBands[0];
  }

  /* ===========================================================================
   * 2. IMPACT  (ASIL -> impact rating, + privacy shift)
   * ------------------------------------------------------------------------- */
  function impact(ecu) {
    var sc = SC(), levels = sc.impactLevels;
    var baseLabel = sc.asilToImpact[ecu.asil] || "Negligible";
    var baseIdx = levels.indexOf(baseLabel);
    var pia = !!ecu.pia, maxIdx = levels.length - 1;
    var idx = Math.min(baseIdx + (pia ? sc.piaShift : 0), maxIdx);
    return {
      label: levels[idx], idx: idx, baseLabel: baseLabel, baseIdx: baseIdx,
      piaApplied: pia && idx > baseIdx, capped: pia && baseIdx + sc.piaShift > maxIdx
    };
  }

  /* ===========================================================================
   * 3. WEIGHT  (Table H.8 lookup, capped)
   * ------------------------------------------------------------------------- */
  function weight(ecu) {
    var sc = SC(), im = impact(ecu), fe = feasibility(ecu);
    var raw = sc.h8[im.label][fe.col];
    var w = Math.min(raw, sc.weightMax);
    return { w: w, raw: raw, impact: im, feasibility: fe };
  }

  /* ===========================================================================
   * 4. PER-COMPONENT RESULT + VEHICLE AGGREGATION
   * ------------------------------------------------------------------------- */
  function starScoreOf(ecu) {
    var r = VRA.component.starScore(ecu.findings);
    return r.critical ? { critical: true, s: null } : { critical: false, s: r.s };
  }

  function rate(ecu) {
    var W = weight(ecu), st = starScoreOf(ecu);
    var s = st.critical ? null : st.s;
    return {
      ecu: ecu, critical: st.critical,
      starScore: s == null ? null : round(s), scoreRaw: s,
      weight: W.w, impact: W.impact, feasibility: W.feasibility,
      contribution: s == null ? null : s * W.w
    };
  }

  /**
   * Aggregate an arbitrary set of components into one vehicle rating.
   * Pure: does not read or mutate config.ecus — the simulation feeds synthetic
   * component arrays here so it runs the SAME weight + star score + aggregation path
   * as the live reference vehicle.
   *   R = Σ(sᵢ·wᵢ) / Σ(wᵢ)   over CS-relevant components.
   * Components flagged CRITICAL at the component level are reported and held
   * out of the mean (their risk is escalated, not averaged away).
   */
  function rateSet(ecus) {
    var rows = ecus.map(rate);
    var sumSW = 0, sumW = 0, criticals = [];
    rows.forEach(function (r) {
      if (r.critical) { criticals.push(r.ecu.name); return; }
      sumSW += r.scoreRaw * r.weight; sumW += r.weight;
    });
    var R = sumW > 0 ? sumSW / sumW : SC().starScore.max;
    return { R: R, Rrounded: round(R), sumSW: round(sumSW), sumW: sumW, rows: rows, criticals: criticals };
  }

  /** The live reference vehicle: rateSet over the config roster. */
  function rating() { return rateSet(CFG().ecus); }

  /* Weight-sensitivity sweep: perturb the two judgement calls a reviewer might
   * question, the star score slope and every Table H.8 weight, by a percentage and
   * see how little the vehicle rating actually moves. Restores config after. */
  function sensitivity() {
    var st = SC().starScore, h8 = SC().h8;
    var baseSlope = st.slope;
    var baseH8 = {}; Object.keys(h8).forEach(function (k) { baseH8[k] = h8[k].slice(); });
    var pcts = [-20, -15, -10, -5, 0, 5, 10, 15, 20];
    var out = pcts.map(function (pct) {
      var f = 1 + pct / 100;
      st.slope = baseSlope * f;
      Object.keys(h8).forEach(function (k) {
        h8[k] = baseH8[k].map(function (w) { return Math.max(1, Math.min(5, Math.round(w * f))); });
      });
      var R = rateSet(CFG().ecus).R;
      return { pct: pct, R: R };
    });
    st.slope = baseSlope;
    Object.keys(h8).forEach(function (k) { h8[k] = baseH8[k].slice(); });
    var vals = out.map(function (o) { return o.R; });
    return { points: out, min: Math.min.apply(null, vals), max: Math.max.apply(null, vals), spread: Math.max.apply(null, vals) - Math.min.apply(null, vals) };
  }

  /* ===========================================================================
   * 5. VERIFICATION & VALIDATION
   * ------------------------------------------------------------------------- */
  function check(desc, expected, got, ref) {
    return { desc: desc, expected: String(expected), got: String(got), pass: String(expected) === String(got), ref: ref };
  }
  function E(av, ac, pr, ui) { return exploitability({ av: av, ac: ac, pr: pr, ui: ui }); }

  function verify() {
    var sc = SC(), groups = [];

    // (a) Exploitability formula E = 8.22 * V * C * P * U  (Annex G.3 bounds 0.12 .. 3.89)
    groups.push({
      name: "Exploitability  E = 8.22\u00B7V\u00B7C\u00B7P\u00B7U", ref: "ISO/SAE 21434 Annex G.3",
      cases: [
        check("max vector N/L/N/N \u2192 3.89", "3.89", round(E("N", "L", "N", "N")), "G.3 upper bound"),
        check("min vector P/H/H/R \u2192 0.12", "0.12", round(E("P", "H", "H", "R")), "G.3 lower bound"),
        check("CVE-2019-18827 N/H/N/N \u2192 2.22", "2.22", round(E("N", "H", "N", "N")), "NVD vector"),
        check("CVE-2017-5579 L/L/L/N \u2192 1.83", "1.83", round(E("L", "L", "L", "N")), "NVD vector")
      ]
    });

    // (b) Table G.8 feasibility bands (boundaries)
    function bl(e) { return bandOf(e).label; }
    groups.push({
      name: "Feasibility bands  (Table G.8)", ref: "ISO/SAE 21434 Table G.8",
      cases: [
        check("0.12 \u2192 Very Low", "Very Low", bl(0.12)),
        check("1.05 \u2192 Very Low", "Very Low", bl(1.05)),
        check("1.06 \u2192 Low",      "Low",      bl(1.06)),
        check("1.99 \u2192 Low",      "Low",      bl(1.99)),
        check("2.00 \u2192 Medium",   "Medium",   bl(2.00)),
        check("2.95 \u2192 Medium",   "Medium",   bl(2.95)),
        check("2.96 \u2192 High",     "High",     bl(2.96)),
        check("3.89 \u2192 High",     "High",     bl(3.89))
      ]
    });

    // (c) Table H.8 risk matrix reproduces the Table H.9 worked examples
    function h8(imp, col) { return sc.h8[imp][col]; }
    groups.push({
      name: "Risk matrix  (Table H.8 \u2192 reproduces Table H.9)", ref: "ISO/SAE 21434 Table H.8 / H.9",
      cases: [
        check("Spoofing: Severe & High \u2192 5",   "5", h8("Severe", 3), "H.9 row 1 (S:5)"),
        check("DoS: Moderate & Low \u2192 2",       "2", h8("Moderate", 1), "H.9 row 2 (O:2)"),
        check("Negligible row is all 1s",           "1,1,1,1", sc.h8.Negligible.join(","), "H.8"),
        check("Severe row is 2,3,4,5",              "2,3,4,5", sc.h8.Severe.join(","), "H.8")
      ]
    });

    // (d) Independent cross-check via Table H.10 formula R = 1 + I x F on the H.9 examples
    function rIF(imp, feas) {
      var h = sc.h10; return h.riskConstant + h.impactValue[imp] * h.feasibilityValue[feas];
    }
    groups.push({
      name: "Cross-check  R = 1 + I\u00D7F  (Table H.10 on H.9)", ref: "ISO/SAE 21434 Table H.10",
      cases: [
        check("Spoofing: 1 + 2\u00D72 \u2192 5", "5", rIF("Severe", "High"), "matches H.8 = 5"),
        check("DoS: 1 + 1\u00D71 \u2192 2",      "2", rIF("Moderate", "Low"), "matches H.8 = 2")
      ]
    });

    // (f) Feasibility dilution — the star score's case weights are propagated to the
    // exploitability E, so BOTH Table H.8 axes react to a component's findings
    // by the same rule (one auditable decision, less assessor subjectivity).
    function feasE(fs) { return feasibility({ netInteraction: "Con", findings: fs }).E.toFixed(2); }
    var fN = { cvss: 5.0, category: "Networks", av: "N", ac: "L", pr: "N", ui: "N" };   // E0 = 3.89 (worst by base)
    var fS = { cvss: 4.0, category: "Software", av: "P", ac: "L", pr: "N", ui: "N" };   // E1 = 0.91
    var fD = { cvss: 3.0, category: "Diagnostics", av: "A", ac: "L", pr: "N", ui: "N" }; // E2 = 2.84
    var fWorst = { cvss: 6.0, category: "Networks", av: "N", ac: "L", pr: "N", ui: "N" }; // >= 5.3 -> worst-case
    groups.push({
      name: "Feasibility dilution  (star score weights propagated to E)", ref: "same 0.6/0.4 \u00B7 0.6/0.3/0.1 on both axes",
      cases: [
        check("case 1 (1 category) \u2192 E = E0", "3.89", feasE([fN])),
        check("case 2 \u2192 0.6\u00B7E0 + 0.4\u00B7E1", "2.70", feasE([fN, fS])),
        check("case 3 \u2192 0.6\u00B7E0 + 0.3\u00B7E1 + 0.1\u00B7E2", "2.89", feasE([fN, fS, fD])),
        check("worst-case (\u2265 5.3) \u2192 E = E0 (single)", "3.89", feasE([fWorst, fS])),
        check("case 2 is the weighted blend, NOT the mean (\u2260 2.40)", "true", String(feasE([fN, fS]) !== "2.40")),
        check("feasibility weights match the star score's case weights", "0.6,0.4|0.6,0.3,0.1",
          SC().starScore.caseWeights["2"].join(",") + "|" + SC().starScore.caseWeights["3"].join(","))
      ]
    });

    // (g) Shift mechanics: interaction (row/feasibility) and privacy (impact)
    function feasLabelFor(net, findings) {
      return feasibility({ netInteraction: net, findings: findings || [] }).label;
    }
    var hiFinding = [{ cvss: 4.0, category: "Networks", av: "N", ac: "L", pr: "N", ui: "N" }]; // E = 3.89 -> High
    var loFinding = [{ cvss: 4.0, category: "Networks", av: "P", ac: "L", pr: "N", ui: "N" }]; // E = 0.91 -> Very Low
    function impLabelFor(asil, pia) { return impact({ asil: asil, pia: pia }).label; }
    groups.push({
      name: "Shift mechanics  (interaction row, privacy column)", ref: "network-interaction & PIA shifts",
      cases: [
        check("clean + Con \u2192 Very Low",              "Very Low", feasLabelFor("Con", [])),
        check("Very Low base + E-D (+1) \u2192 Low",      "Low",      feasLabelFor("E-D", loFinding)),
        check("Very Low base + E-C (+2) \u2192 Medium",   "Medium",   feasLabelFor("E-C", loFinding)),
        check("High + E-C \u2192 High (capped)",          "High",     feasLabelFor("E-C", hiFinding)),
        check("ASIL B \u2192 Major (no PIA)",             "Major",    impLabelFor("B", false)),
        check("ASIL B + PIA \u2192 Severe",               "Severe",   impLabelFor("B", true)),
        check("ASIL D + PIA \u2192 Severe (capped)",      "Severe",   impLabelFor("D", true))
      ]
    });

    // (h) Reference-component weights (end-to-end)
    function wOf(id) { var e = CFG().ecus.filter(function (x) { return x.id === id; })[0]; return e ? weight(e).w : "?"; }
    groups.push({
      name: "Reference component weights  (end-to-end)", ref: "config roster + H.8",
      cases: [
        check("Main ADAS Controller (D, E-D, clean) \u2192 3", "3", wOf("adasc")),
        check("Driving Automation Unit (D, E-C, clean) \u2192 4", "4", wOf("adu")),
        check("Infotainment Head Unit (QM+PIA, E-C, 2 vulns) \u2192 2", "2", wOf("hu")),
        check("Body Control Module (A, E-D, 3 vulns/Case 3) \u2192 3", "3", wOf("bcm")),
        check("Door Control (QM, E-E, 1 vuln) \u2192 1", "1", wOf("door"))
      ]
    });

    // (g) Aggregation properties
    var save = CFG().ecus;
    // all-clean vehicle -> R = 5
    var allClean = save.map(function (e) { return { asil: e.asil, pia: e.pia, netInteraction: e.netInteraction, findings: [] }; });
    CFG().ecus = allClean; var Rclean = rating().Rrounded; CFG().ecus = save;
    // real reference vehicle
    var Rref = rating().Rrounded;
    // Same finding on a high- vs low-weight component, each next to a clean anchor:
    // the high-weight placement must pull the vehicle rating down further.
    var f = [{ cve: "x", cvss: 5.9, category: "Networks", av: "N", ac: "H", pr: "N", ui: "N" }]; // s = 0.72
    var anchor = { asil: "QM", pia: false, netInteraction: "Con", findings: [] };                // clean, w = 1
    CFG().ecus = [anchor, { asil: "D",  pia: false, netInteraction: "E-C", findings: f }]; var Rhi = rating().R; CFG().ecus = save; // w = 5
    CFG().ecus = [anchor, { asil: "QM", pia: false, netInteraction: "Con", findings: f }]; var Rlo = rating().R; CFG().ecus = save; // w = 1
    groups.push({
      name: "Aggregation properties  R = \u03A3(s\u00B7w)/\u03A3(w)", ref: "vehicle rating equation",
      cases: [
        check("every component scores 5 \u2192 R = 5.00", "5", Rclean, "no-finding vehicle"),
        check("same finding lowers R more on a high-weight ECU", "true", String(Rhi < Rlo), "R_hi " + round(Rhi) + " < R_lo " + round(Rlo)),
        check("reference vehicle R reproduces " + Rref, String(Rref), Rref, "regression anchor")
      ]
    });

    /* (h) Weight sensitivity — R must not hinge on the exact weight values, and
     * the sweep must leave the config exactly as it found it. */
    var Rbefore = rating().Rrounded;
    var sens = sensitivity();
    var Rafter = rating().Rrounded;
    groups.push({
      name: "Weight sensitivity  (robustness to the weights)", ref: "\u00B120% on slope + Table H.8",
      cases: [
        check("R stays inside [0, 5] across the whole sweep", "true",
          String(sens.points.every(function (p) { return p.R >= 0 && p.R <= 5; }))),
        check("spread under \u00B120% is small (< 0.6 on a 0\u20135 scale)", "true", String(sens.spread < 0.6)),
        check("the sweep restores config exactly (R unchanged)", String(Rbefore), Rafter)
      ]
    });

    return groups;
  }

  /* ===========================================================================
   * 6. RENDERING
   * ------------------------------------------------------------------------- */
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
  /* Star icon at nearest-half resolution (display only — the exact rating is
   * shown as the number beside it). 3.65 → 3 full + 1 half gold, rest grey. */
  function stars(v) {
    var gold = Math.round(v * 2) / 2, out = "";
    for (var i = 1; i <= 5; i++) {
      var cls = gold >= i ? "on" : (gold >= i - 0.5 ? "half" : "off");
      out += "<span class='" + cls + "'>\u2605</span>";
    }
    return "<span class='stars'>" + out + "</span>";
  }

  function renderSummary(res) {
    var crit = res.criticals.length
      ? "<div class='veh-crit'>\u26A0 " + res.criticals.length + " component(s) flagged CRITICAL and excluded from the mean: " + esc(res.criticals.join(", ")) + "</div>"
      : "";
    return "<div class='veh-summary'>" +
      "<div class='veh-R'><div class='veh-R-num'>" + res.Rrounded.toFixed(2) + "</div>" + stars(res.Rrounded) +
      "<div class='veh-R-lab'>Vehicle rating &nbsp;R = \u03A3(s\u00B7w) / \u03A3(w)</div></div>" +
      "<div class='veh-R-calc'><span>\u03A3(s\u00B7w) = " + res.sumSW.toFixed(2) + "</span><span>\u03A3(w) = " + res.sumW + "</span>" +
      "<span>components = " + res.rows.length + "</span></div></div>" + crit;
  }

  function renderTable(res) {
    var rows = res.rows.map(function (r, i) {
      var im = r.impact, fe = r.feasibility, e = r.ecu;
      var impCell = im.baseLabel + (im.piaApplied ? " <span class='shift'>+PIA\u2192" + im.label + "</span>" : "");
      var feaCell = fe.clean ? "none" : (fe.baseLabel + (fe.shift ? " <span class='shift'>+" + fe.shift + "\u2192" + fe.label + "</span>" : ""));
      var scoreCell = r.critical ? "<span class='crit'>CRIT</span>" : r.starScore.toFixed(2);
      var contrib = r.critical ? "n/a" : r.contribution.toFixed(2);
      return "<tr data-i='" + i + "'>" +
        "<td>" + esc(e.name) + "</td>" +
        "<td class='dim mono'>" + esc(e.ref) + "</td>" +
        "<td class='dim'>" + e.asil + "</td>" +
        "<td>" + impCell + "</td>" +
        "<td>" + feaCell + "</td>" +
        "<td class='n'><b>" + r.weight + "</b></td>" +
        "<td class='n'>" + scoreCell + "</td>" +
        "<td class='n'>" + contrib + "</td></tr>";
    }).join("");
    return "<div class='veh-wrap'><table class='veh'><thead><tr>" +
      "<th>Component</th><th>Ref</th><th>ASIL</th><th>Impact</th><th>Feasibility</th>" +
      "<th class='n'>w</th><th class='n'>s</th><th class='n'>s\u00B7w</th></tr></thead><tbody>" +
      rows + "</tbody></table></div>";
  }

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

  function renderDerivation(r) {
    var im = r.impact, fe = r.feasibility;
    var out = "<div class='dv-title'><b>" + esc(r.ecu.name) + "</b>: weight &amp; contribution</div>";
    out += "<div class='dv-step'><span class='dv-k'>Impact</span>ASIL " + r.ecu.asil + " \u2192 " + im.baseLabel +
      (im.piaApplied ? "; PIA confirms PII \u2192 +1 \u2192 <b>" + im.label + "</b>" + (im.capped ? " (capped)" : "") : " \u2192 <b>" + im.label + "</b>") + "</div>";
    if (fe.clean) {
      out += "<div class='dv-step'><span class='dv-k'>Feasibility</span>no confirmed finding \u2192 base " + fe.baseLabel + "</div>";
    } else {
      var es = fe.Es.map(function (e, i) { return { w: (fe.weights[i] || 0), e: e }; })
        .filter(function (t) { return t.w > 0; })
        .map(function (t) { return t.w + "\u00B7" + t.e.toFixed(2); }).join(" + ");
      out += "<div class='dv-step'><span class='dv-k'>Feasibility</span>E = " + es +
        " = " + fe.E.toFixed(2) + " \u2192 " + fe.baseLabel + " (Table G.8)</div>";
    }
    out += "<div class='dv-step'><span class='dv-k'>Interaction</span>" + r.ecu.netInteraction + " \u2192 +" + fe.shift +
      " \u2192 feasibility <b>" + fe.label + "</b>" + (fe.capped ? " (capped at High)" : "") + "</div>";
    out += "<div class='dv-step'><span class='dv-k'>Weight</span>H.8[" + im.label + "][" + fe.label + "] = <b>" + r.weight + "</b></div>";
    if (r.critical) {
      out += "<div class='dv-step crit-step'><span class='dv-k'>Star score</span>component flagged <b>CRITICAL</b>, so it is left out of the mean</div>";
    } else {
      out += "<div class='dv-step'><span class='dv-k'>Contribution</span>s\u00B7w = " + r.starScore.toFixed(2) + " \u00D7 " + r.weight +
        " = <b>" + r.contribution.toFixed(2) + "</b></div>";
    }
    return out;
  }

  function wireRows(res) {
    var host = document.getElementById("vehicle-app");
    if (!host) return;
    var detail = host.querySelector("#veh-deriv");
    host.querySelectorAll("table.veh tbody tr").forEach(function (tr) {
      tr.addEventListener("click", function () {
        host.querySelectorAll("table.veh tbody tr").forEach(function (t) { t.classList.remove("sel"); });
        tr.classList.add("sel");
        if (detail) detail.innerHTML = renderDerivation(res.rows[+tr.getAttribute("data-i")]);
      });
    });
  }

  /* Full mathematical flow for one affected component: the star score derivation
   * (Algorithm 1) followed by the vehicle-level weight and contribution. Shown
   * in the step-by-step summary so a reader can follow one ECU end to end. */
  function explainFlow(ecu) {
    var comp = (VRA.component && VRA.component.explain) ? VRA.component.explain(ecu) : "";
    var veh = renderDerivation(rate(ecu));
    return "<div class='fx-half'><div class='fx-tag'>1 &middot; Component Stars</div>" + comp + "</div>" +
      "<div class='fx-join'>then at the vehicle level</div>" +
      "<div class='fx-half'><div class='fx-tag'>2 &middot; Vehicle Stars</div>" + veh + "</div>";
  }
  function initFlowExplorer() {
    var picker = document.getElementById("fx-picker"), out = document.getElementById("fx-out");
    if (!picker || !out) return;
    var affected = CFG().ecus.filter(function (e) { return (e.findings || []).length > 0; });
    if (!affected.length) { picker.innerHTML = "<span class='muted'>No affected components in this car.</span>"; return; }
    picker.innerHTML = affected.map(function (e) { return "<button type='button' class='fx-btn' data-id='" + e.id + "'>" + esc(e.name) + "</button>"; }).join("");
    function show(id) {
      var e = CFG().ecus.filter(function (x) { return x.id === id; })[0];
      if (!e) return;
      picker.querySelectorAll(".fx-btn").forEach(function (b) { b.classList.toggle("sel", b.getAttribute("data-id") === id); });
      out.innerHTML = explainFlow(e);
    }
    picker.querySelectorAll(".fx-btn").forEach(function (b) { b.addEventListener("click", function () { show(b.getAttribute("data-id")); }); });
    show(affected[0].id);
  }

  /* ===========================================================================
   * 7. INIT
   * ------------------------------------------------------------------------- */
  VRA.vehicle = {
    exploitability: exploitability, feasibility: feasibility, impact: impact,
    weight: weight, rate: rate, rateSet: rateSet, rating: rating, sensitivity: sensitivity, verify: verify,
    init: function () {
      if (!VRA.config || !VRA.component) return;
      var res = rating();
      var app = document.getElementById("vehicle-app");
      if (app) {
        app.innerHTML =
          "<div class='comp-note'>The component star scores are aggregated with each component's Table H.8 weight. " +
          "Impact from ASIL, feasibility from the CVSS exploitability of confirmed vulnerabilities. Click a row for its derivation.</div>" +
          renderSummary(res) + renderTable(res) + "<div id='veh-deriv' class='deriv'></div>";
        wireRows(res);
        var first = app.querySelector("table.veh tbody tr");
        if (first) first.click();
      }
      var vnv = document.getElementById("vehicle-vnv");
      if (vnv) vnv.innerHTML = renderVnV();
      initFlowExplorer();
    }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", VRA.vehicle.init);
  else VRA.vehicle.init();
})();
