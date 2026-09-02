import assert from "node:assert/strict";
import test from "node:test";
import { assertVisibleText, disabledCount, pageText } from "../src/assert.mjs";

test("assertVisibleText targets the first matching element and waits for visibility", async () => {
  const calls = [];
  const locator = {
    first() {
      calls.push(["first"]);
      return this;
    },
    async waitFor(options) {
      calls.push(["waitFor", options]);
    },
  };
  const page = {
    getByText(text) {
      calls.push(["getByText", text]);
      return locator;
    },
  };

  await assertVisibleText(page, "Ready");

  assert.deepEqual(calls, [
    ["getByText", "Ready"],
    ["first"],
    ["waitFor", { state: "visible" }],
  ]);
});

test("assertVisibleText propagates driver failures", async () => {
  const failure = new Error("locator detached");
  const page = {
    getByText() {
      return {
        first() {
          return {
            waitFor() {
              throw failure;
            },
          };
        },
      };
    },
  };

  await assert.rejects(() => assertVisibleText(page, "Ready"), failure);
});

test("disabledCount evaluates the supplied selector and returns the element count", async () => {
  const calls = [];
  const page = {
    async $$eval(selector, visitor) {
      calls.push(selector);
      return visitor([{}, {}, {}]);
    },
  };

  assert.equal(await disabledCount(page, "button:disabled"), 3);
  assert.deepEqual(calls, ["button:disabled"]);
});

test("disabledCount propagates browser evaluation failures", async () => {
  const failure = new Error("execution context destroyed");
  const page = {
    async $$eval() {
      throw failure;
    },
  };

  await assert.rejects(() => disabledCount(page, "button:disabled"), failure);
});

test("pageText reads only the document body", async () => {
  const calls = [];
  const page = {
    async $eval(selector, visitor) {
      calls.push(selector);
      return visitor({ textContent: "Fiducia ready" });
    },
  };

  assert.equal(await pageText(page), "Fiducia ready");
  assert.deepEqual(calls, ["body"]);
});

for (const textContent of [null, undefined]) {
  test(`pageText normalizes ${String(textContent)} text content to an empty string`, async () => {
    const page = {
      async $eval(_selector, visitor) {
        return visitor({ textContent });
      },
    };

    assert.equal(await pageText(page), "");
  });
}
