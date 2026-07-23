#include "tree_sitter/parser.h"

// External scanner for Cloudflare rules-language RAW STRINGS.
//
// Raw strings are Rust-style: `r"..."`, `r#"..."#`, `r##"..."##`, ... with 0 to
// 255 `#` delimiters. No escape processing happens inside them; the string ends
// at the first `"` followed by the same number of `#` characters that opened it.
// This can't be expressed as a tree-sitter regex token (the closing delimiter's
// hash count must match the opening one, and content may contain `"` that is not
// a terminator), so it lives here.

enum TokenType {
  RAW_STRING,
};

void *tree_sitter_cloudflare_external_scanner_create(void) { return 0; }
void tree_sitter_cloudflare_external_scanner_destroy(void *payload) {}
unsigned tree_sitter_cloudflare_external_scanner_serialize(void *payload,
                                                           char *buffer) {
  return 0;
}
void tree_sitter_cloudflare_external_scanner_deserialize(void *payload,
                                                         const char *buffer,
                                                         unsigned length) {}

static inline void advance(TSLexer *lexer) { lexer->advance(lexer, false); }
static inline void skip(TSLexer *lexer) { lexer->advance(lexer, true); }

bool tree_sitter_cloudflare_external_scanner_scan(void *payload, TSLexer *lexer,
                                                  const bool *valid_symbols) {
  if (!valid_symbols[RAW_STRING]) {
    return false;
  }

  // Skip any leading whitespace before the literal.
  while (lexer->lookahead == ' ' || lexer->lookahead == '\t' ||
         lexer->lookahead == '\n' || lexer->lookahead == '\r') {
    skip(lexer);
  }

  if (lexer->lookahead != 'r') {
    return false;
  }
  advance(lexer);

  // Count the opening `#` delimiters (0..=255).
  unsigned opening_hashes = 0;
  while (lexer->lookahead == '#') {
    opening_hashes++;
    if (opening_hashes > 255) {
      return false;
    }
    advance(lexer);
  }

  if (lexer->lookahead != '"') {
    return false;
  }
  advance(lexer);

  // Consume content until a `"` followed by `opening_hashes` `#` characters.
  for (;;) {
    if (lexer->eof(lexer)) {
      return false; // unterminated raw string
    }
    if (lexer->lookahead == '"') {
      advance(lexer);
      unsigned closing_hashes = 0;
      while (closing_hashes < opening_hashes && lexer->lookahead == '#') {
        closing_hashes++;
        advance(lexer);
      }
      if (closing_hashes == opening_hashes) {
        lexer->result_symbol = RAW_STRING;
        lexer->mark_end(lexer);
        return true;
      }
      // Not the terminator: the `"` and any `#` consumed are string content.
    } else {
      advance(lexer);
    }
  }
}
