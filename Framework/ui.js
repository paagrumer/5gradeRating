/* =============================================================================
 * VRA — Vehicle Rating & Assessment  ·  Module: UI  (shell navigation)
 * -----------------------------------------------------------------------------
 * Three-way tab navigation for the shell:
 *   architecture — 01: how E/E architecture evolves (illustrative only)
 *   model       — 02+03: the worked example (Component + Vehicle Stars)
 *   simulator   — 04: fleet simulation (scalability)
 *   details     — expert quick-learning: references, decisions, testing
 *   management  — plain-language view for non-technical readers
 *
 * Pure presentation glue; holds no data or scoring logic. Buttons carry
 * data-tab-btn="<name>" and panels carry data-tab="<name>".
 *
 * Public API
 *   VRA.ui.show(name) — reveal one tab, hide the others
 *   VRA.ui.init()     — wire the buttons (auto on load); defaults to "simulator"
 * ========================================================================== */
(function () {
  "use strict";
  var VRA = (window.VRA = window.VRA || {});

  VRA.ui = {
    /** Show one panel by name and mark its button active. */
    show: function (name) {
      var panels = document.querySelectorAll("[data-tab]");
      var buttons = document.querySelectorAll("[data-tab-btn]");
      Array.prototype.forEach.call(panels, function (p) {
        p.hidden = p.getAttribute("data-tab") !== name;
      });
      Array.prototype.forEach.call(buttons, function (b) {
        var on = b.getAttribute("data-tab-btn") === name;
        b.classList.toggle("active", on);
        b.setAttribute("aria-selected", on ? "true" : "false");
      });
      // move focus to the top of the newly shown panel for accessibility
      var active = document.querySelector('[data-tab="' + name + '"]');
      if (active) window.scrollTo({ top: 0, behavior: "auto" });
    },

    init: function () {
      var buttons = document.querySelectorAll("[data-tab-btn]");
      if (!buttons.length) return;
      Array.prototype.forEach.call(buttons, function (b) {
        b.addEventListener("click", function () { VRA.ui.show(b.getAttribute("data-tab-btn")); });
        b.addEventListener("keydown", function (e) {
          // left/right arrow navigation between tabs
          if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
          var list = Array.prototype.slice.call(buttons);
          var i = list.indexOf(b);
          var next = e.key === "ArrowRight" ? (i + 1) % list.length : (i - 1 + list.length) % list.length;
          list[next].focus(); list[next].click();
        });
      });
      VRA.ui.show("architecture");
    }
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", VRA.ui.init);
  else VRA.ui.init();
})();
