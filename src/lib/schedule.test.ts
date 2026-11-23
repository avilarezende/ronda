import assert from "node:assert/strict";
import test from "node:test";
import { formatUpdateHour, nextUpdate } from "./schedule";

test("the next collection after 07h Fortaleza is 08h", () => {
  assert.equal(nextUpdate(new Date("2026-11-23T10:30:00.000Z")).toISOString(), "2026-11-23T11:00:00.000Z");
});

test("the next collection after 20h Fortaleza is 02h", () => {
  assert.equal(nextUpdate(new Date("2026-11-23T23:30:00.000Z")).toISOString(), "2026-11-24T05:00:00.000Z");
});

test("formats the Fortaleza hour of a slot", () => {
  assert.equal(formatUpdateHour("2026-11-23T11:00:00.000Z"), "08h");
  assert.equal(formatUpdateHour("2026-11-24T05:00:00.000Z"), "02h");
});
