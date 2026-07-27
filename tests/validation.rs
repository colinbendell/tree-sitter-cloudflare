//! Integration tests for the Cloudflare grammar.
//!
//! [`parses_without_error`] runs fully offline and is the default gate.
//! [`validate_against_cloudflare_api`] is `#[ignore]`d because it needs network
//! access and a `CLOUDFLARE_API_TOKEN`; run it explicitly with:
//!
//! ```sh
//! CLOUDFLARE_API_TOKEN=... cargo test -- --ignored
//! ```

use tree_sitter::Parser;

/// Sample expressions that must parse cleanly (no ERROR / MISSING nodes) and,
/// when checked, be accepted by Cloudflare's validation endpoint.
const VALID_EXPRESSIONS: &[&str] = &[
    r#"http.host eq "example.com""#,
    r#"ip.src eq 2001:db8::1"#,
    r#"ip.src in {2001:db8::/32 192.0.2.0/24}"#,
    r#"http.host eq "a \"quoted\" value""#,
    r#"bit_slice("udp", 64, 80) == 1"#,
    r#"is_timed_hmac_valid_v0("secret", http.request.uri, 100000, http.request.timestamp.sec, 8, "s")"#,
    "cf.edge.server_port eq 80 or (cf.edge.server_port == 443 && ssl)",
    "not cf.client.bot",
];

fn parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cloudflare::LANGUAGE.into())
        .expect("Error loading Cloudflare parser");
    parser
}

#[test]
fn parses_without_error() {
    let mut parser = parser();
    for expr in VALID_EXPRESSIONS {
        let tree = parser.parse(expr, None).expect("parse returned None");
        assert!(
            !tree.root_node().has_error(),
            "expected `{expr}` to parse without errors, got:\n{}",
            tree.root_node().to_sexp()
        );
    }
}

/// Cross-checks each sample expression against Cloudflare's public
/// `validate-expr` endpoint. Requires network access and `CLOUDFLARE_API_TOKEN`.
#[test]
#[ignore = "requires network access and CLOUDFLARE_API_TOKEN"]
fn validate_against_cloudflare_api() -> anyhow::Result<()> {
    let token = std::env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| anyhow::anyhow!("CLOUDFLARE_API_TOKEN not set"))?;
    let client = reqwest::blocking::Client::new();
    for expr in VALID_EXPRESSIONS {
        let url = reqwest::Url::parse_with_params(
            "https://api.cloudflare.com/client/v4/filters/validate-expr",
            &[("expression", *expr)],
        )?;
        let response = client.get(url).bearer_auth(&token).send()?;
        assert!(
            response.status().is_success(),
            "`{expr}` failed validation: HTTP {}",
            response.status()
        );
    }
    Ok(())
}
