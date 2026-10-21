/**
 * Code-review finding: scene.js (Three.js rendering) and main.js (the HUD
 * legend) used to each hardcode their own independent copy of the same
 * six disposition/diff colors. They happened to agree byte-for-byte, but
 * nothing enforced that -- a future edit to one disposition's color in
 * scene.js would have silently desynced the legend swatch from the
 * actual rendered node color, with no test to catch it. This module is
 * now the ONE place those colors are defined, as CSS hex strings (the
 * form main.js needs directly for inline styles); scene.js converts them
 * to Three.js color ints via toThreeHex() rather than keeping its own copy.
 */

/** Disposition -> swatch color. "none" covers a node with no finding
 * attached at all (worst_disposition === null/undefined). */
export const STATUS_COLOR = {
  VERIFIED_TRUE: "#ff5c5c",
  TOOL_FAILURE: "#ff5c5c",
  UNRESOLVED_INCONCLUSIVE: "#f5c84c",
  VERIFIED_FALSE: "#5ad1a0",
  none: "#3c4a63",
};

/** Milestone 22 diff-mode colors, deliberately distinct from STATUS_COLOR
 * so "this changed since the baseline" never reads as just another
 * disposition. "unchanged" intentionally reuses the same slate as "none"
 * above -- both mean "shown for orientation, not itself a match." */
export const DIFF_COLOR = {
  new: "#d44fe0", // a node that did not exist at all in the baseline scan
  changed: "#ff9d42", // same node, but its finding_uids or worst_disposition differ
  unchanged: "#3c4a63",
};

/** @param {string} hex e.g. "#ff5c5c" @returns {number} 0xff5c5c, for Three.js Color/material fields. */
export function toThreeHex(hex) {
  return parseInt(hex.slice(1), 16);
}
