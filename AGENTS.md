# AGENTS.md

Guidance for AI agents and contributors working in this repo.

## What this is

A [tree-sitter](https://tree-sitter.github.io/tree-sitter/) grammar for the
**Cloudflare Ruleset Engine "rules language"** —
([reference](https://developers.cloudflare.com/ruleset-engine/rules-language/)).
It parses expressions like:

```
http.host eq "example.com" and ip.src in {1.2.3.4 2001:db8::/32} and not cf.client.bot
```

## Stop conditions

Check these before any task. Stop and say so before touching files if any apply.

- Never commit unless explicitly asked.
- More than 3 unplanned files? Stop and explain why.
- Always target `main` as the PR base. Do not commit to `main`

## JavaScript

- **JavaScript, not TypeScript.** `.js` and `.jsx` only. JSDoc annotations where types add clarity.
- **Server actions for mutations; API routes for external consumers only.**
- Simple over clever. Inline single-use logic; extract a shared helper when the same logic appears more than once.

## Rules

1. **Inspect before touching.** Read the relevant files first. State your assumptions\
   and proceed; stop to ask only when a wrong guess is expensive to undo.
2. **Smallest change that solves the task.** No drive-by cleanup of unrelated code.\
   Refactoring the task genuinely requires is fine; everything else is not.
3. **Tests accompany behavior changes.** New behavior ships with a test covering the\
   happy path plus at least one failure case. Bug fixes ship with a failing test that\
   reproduces the bug. Tests are colocated directly beside the file under test (no\
   `__tests__/` folder), named `<subject>.test.js(x)`. See `docs/STRUCTURE.md`.
4. **Fix forward.** Never silence a lint rule, test, or type error to make a check pass.\
   Fix the cause. A red check is an unfinished task, not a known issue to file later.
5.  **Validate narrowly while working; run the full gate before a PR.**\
    Run targeted checks as you go (the specific test, typecheck on the file you touched).\
    Before a PR: `npm run format && npm run lint`, then `npm test` if logic changed, then\
    `npm run build`. Use `npm run validate:check` (not `validate`) to verify without auto-fixing.
6.  **Verify end-to-end before claiming done.** For UI changes, start the dev server and\
    exercise the golden path plus edge cases in a browser. Type-check green is not done\
    for a feature. If the UI cannot be tested in this environment, say so explicitly.

## Parallel agents

Multiple agents may work this repo simultaneously via git worktrees. Branches and\
worktrees follow `<username>/<slug>` (e.g. `colin/admin-metrics`), where username is\
the GitHub username (`gh api user --jq .login`) or `whoami` as fallback. Before\
touching any domain, check the shared lock registry for an active lock. The registry\
lives in the main repo and every worktree resolves to it the same way:\
`LOCK_DIR="$(git rev-parse --git-common-dir)/../.context/locks"`. Do **not** use a plain\
`.context/locks/` path -- that writes a private per-worktree copy no one else reads.\
Write your own lock before your first edit; delete it when done. See\
`.context/CONVENTIONS.md` for setup and protocol.

## Source of truth: edit `grammar.js`, never `src/`

- **`grammar.js`** is the ONLY hand-edited grammar file. Everything under `src/`
  (`parser.c`, `grammar.json`, `node-types.json`) and `src/tree_sitter/` is
  **generated** — never edit it by hand.
- After any change to `grammar.js` you MUST regenerate and commit the `src/`
  artifacts so consumers who don't run the CLI get a working parser:

  ```bash
  tree-sitter generate      # regenerates src/parser.c etc.
  tree-sitter test          # runs the corpus tests in test/corpus/
  ```

  If `tree-sitter` isn't on PATH, use `npx tree-sitter` (the CLI is a devDependency).

## Layout

| Path | Purpose |
|------|---------|
| `grammar.js` | The grammar definition (hand-edited). |
| `src/` | Generated C parser + JSON — regenerate, don't edit. |
| `test/corpus/*.txt` | tree-sitter corpus tests (`input → expected S-expression`). |
| `test/validations/` | Go tests that check example expressions against the live Cloudflare API. |
| `queries/highlights.scm` | Syntax-highlighting queries; keep node names in sync with the grammar. |
| `bindings/{node,rust}` | Language bindings. `bindings/rust/lib.rs` re-exports the parser. |
| `examples/*.cfrule` | Sample expressions (the `.cfrule` file type). |

## How the grammar is organized

Fields and functions are grouped **by value type**, which drives what operators
and functions may apply:

- **Fields by type**: `number_field`, `string_field`, `ip_field`, `bool_field`,
  `bytes_field`, plus array/map variants (`array_string_field`,
  `map_string_array_field`, …). See the "Cloudflare Ruleset Fields" section.
- **Functions by return type**: `string_func`, `number_func`, `bool_func`,
  `array_func`. Each function has a small builder helper at the bottom of
  `grammar.js` (e.g. `concatFunc`, `lenFunc`).
- **Operators**: `NUMBER_COMPARISON_OPS` / `STRING_COMPARISON_OPS` at the top of
  the file, with both English (`eq`, `ne`) and symbolic (`==`, `!=`) forms.
- **Precedence** (compound_expression): `not` > `and`/`&&` > `xor`/`^^` >
  `or`/`||`.

### Adding a field
Add the exact field name (a quoted string) to the correct `*_field` rule chosen
by the field's value type. Keep the source-grouping comments intact. Add a
corpus test exercising it.

### Adding a function
1. Write a builder helper at the bottom of `grammar.js` following the existing
   pattern (`field("func", "...")`, then `"("`, args, `")"`).
2. Wire it into the `*_func` rule matching its **return type**.
3. Add a corpus test in `test/corpus/functions.txt`.

## Testing

- `tree-sitter test` — corpus tests; the primary gate. Add a case for every
  grammar change (both things that should parse and things that should `ERROR`).
- `cd test/validations && go test` — validates sample expressions against the
  real Cloudflare API; needs `CLOUDFLARE_API_TOKEN`. Optional locally, runs in CI.
- Update a single corpus expectation after an intentional grammar change with
  `tree-sitter test -u`.

## Conventions

- Match the existing comment style that labels field groups ("Standard fields",
  "Magic Firewall fields", "HTTP response fields", …).
- Verify new fields/functions/operators against the current Cloudflare docs
  before adding — the language changes over time.
- One logical change per commit; regenerate `src/` in the same commit as the
  `grammar.js` change that caused it.
