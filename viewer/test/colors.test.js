import { test } from "node:test";
import assert from "node:assert/strict";
import { STATUS_COLOR, DIFF_COLOR, toThreeHex } from "../src/colors.js";

// Code-review finding: scene.js and main.js used to each hardcode their
// own copy of these colors, in sync only by coincidence. Now that both
// import from this one module, the real risk is a malformed hex string
// here silently producing a wrong (or NaN) Three.js color via toThreeHex
// -- these tests guard the shape of the shared source of truth itself.

const ALL_PALETTES = { ...STATUS_COLOR, ...DIFF_COLOR };

test("every shared color is a well-formed 6-digit hex string", () => {
  for (const [key, hex] of Object.entries(ALL_PALETTES)) {
    assert.match(hex, /^#[0-9a-fA-F]{6}$/, `${key} -> ${hex} is not a well-formed hex color`);
  }
});

test("toThreeHex converts every shared color to a finite Three.js int", () => {
  for (const [key, hex] of Object.entries(ALL_PALETTES)) {
    const n = toThreeHex(hex);
    assert.equal(Number.isFinite(n), true, `${key} -> ${hex} produced a non-finite int`);
    assert.equal(n, parseInt(hex.slice(1), 16));
  }
});

test("toThreeHex('#ff5c5c') is the known literal 0xff5c5c", () => {
  assert.equal(toThreeHex("#ff5c5c"), 0xff5c5c);
});

test("tool failure and confirmed finding have distinct colors", () => {
  assert.notEqual(STATUS_COLOR.VERIFIED_TRUE, STATUS_COLOR.TOOL_FAILURE);
});

test("diff 'unchanged' reuses the same color as 'no finding attached' by design", () => {
  assert.equal(DIFF_COLOR.unchanged, STATUS_COLOR.none);
});
