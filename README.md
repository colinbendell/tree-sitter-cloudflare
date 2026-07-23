# tree-sitter-cloudflare

A [tree-sitter](https://tree-sitter.github.io/tree-sitter/) grammar for the
[Cloudflare rules language](https://developers.cloudflare.com/ruleset-engine/rules-language/)
— the expression language used by Cloudflare WAF / firewall rules and Magic
Firewall.

```
http.host eq "example.com" and ip.src in {1.2.3.4 2001:db8::/32} and not cf.client.bot
```

## Usage

**Rust**

```rust
let mut parser = tree_sitter::Parser::new();
parser
    .set_language(&tree_sitter_cloudflare::LANGUAGE.into())
    .expect("Error loading Cloudflare parser");
let tree = parser.parse(r#"http.host eq "example.com""#, None).unwrap();
```

**Node**

```js
import Parser from "tree-sitter";
import Cloudflare from "tree-sitter-cloudflare";

const parser = new Parser();
parser.setLanguage(Cloudflare);
```

## Development

`grammar.js` is the single source of truth; everything under `src/` is
generated. See [AGENTS.md](AGENTS.md) for the full workflow.

```sh
tree-sitter generate   # regenerate src/ from grammar.js
tree-sitter test       # run the corpus tests in test/corpus/
cargo test             # Rust bindings + offline parse checks
```

## Status

Supported: comparison / logical / `in` / wildcard operators, IPv4 & IPv6
literals and CIDR ranges, string (with escapes) / number / boolean values,
arrays and maps, and the documented functions including `bit_slice` and
`is_timed_hmac_valid_v0`.

### TODO

- Move `matches` to use regex capture rather than string capture.
- Add remaining newer functions (`substring`, `wildcard_replace`,
  `decode_base64`, `split`, `join`, `sha256`, JWT helpers, …).

## License

MIT — see [LICENSE](LICENSE).
