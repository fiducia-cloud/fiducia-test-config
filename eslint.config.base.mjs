// Shared ESLint flat-config preset for fiducia.cloud repos.
//
// Adoption is opt-in and additive: a repo that wants linting adds `eslint` +
// `typescript-eslint` as devDeps and re-exports this preset from its own
// eslint.config.mjs:
//
//   import base from "@fiducia/test-config/eslint";
//   export default base;
//
// Node CI runs this as a NON-BLOCKING step where a repo has opted in, so the
// required gates stay: tests + typecheck + audit. This keeps existing repos'
// PRs green while making one shared lint baseline available.

export default [
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "target/**",
      "generated/**",
      "**/*.min.js",
    ],
  },
  {
    files: ["**/*.{js,mjs,ts,mts}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
    },
    linterOptions: {
      reportUnusedDisableDirectives: true,
    },
    rules: {
      "no-var": "error",
      "prefer-const": "error",
      eqeqeq: ["error", "smart"],
      "no-console": "off",
    },
  },
];
