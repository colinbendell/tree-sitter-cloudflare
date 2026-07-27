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
literals, CIDR and `start..end` ranges, quoted (with escapes) and raw
(`r"..."`) strings, number / boolean values, arrays and maps, and the full
documented function set (including
`bit_slice`, `is_timed_hmac_valid_v0`, `cidr`/`cidr6`, `substring`,
`wildcard_replace`, `split`, `join`, `sha256`, base64, and the JWT helpers).
The field set covers ~200 fields across the HTTP, IP/geo, SSL/TLS, mTLS
(`cf.tls_client_auth.*`), Bot Management, WAF (score / content-scan /
credential-check), LLM (`cf.llm.*`), JWT claims, API Gateway, timings, and
Magic Firewall families.

The full documented field set is covered, including the `Map<Array<Integer>>`
JWT time claims and the `Map<Integer>` LLM topic scores.

## License

MIT — see [LICENSE](LICENSE).
