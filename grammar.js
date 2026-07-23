/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

// Comprehensive IPv6 matcher supporting `::` compression, the leading/trailing
// `::` forms, and IPv4-mapped addresses (e.g. `::ffff:192.0.2.1`). Hex groups
// are case-insensitive.
const IPV6 =
  /(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)|(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])/;

const NUMBER_COMPARISON_OPS = [
  "eq",
  "ne",
  "lt",
  "le",
  "gt",
  "ge",
  "==",
  "!=",
  "<",
  "<=",
  ">",
  ">=",
];

const STRING_COMPARISON_OPS = [
  "eq",
  "ne",
  "lt",
  "le",
  "gt",
  "ge",
  "==",
  "!=",
  "<",
  "<=",
  ">",
  ">=",
  "contains",
  "strict wildcard",
  "wildcard",
];

// Regex operators. Their right-hand operand is a regular expression, captured
// as a distinct `regex` node (not a plain `string`) so a regex grammar can be
// injected via queries/injections.scm.
const REGEX_OPS = ["matches", "~"];

export default grammar({
  name: "cloudflare",

  extras: ($) => [$.comment, /\s/],

  externals: ($) => [$.raw_string],

  rules: {
    source_file: ($) => repeat($._expression),

    _expression: ($) =>
      choice(
        $.not_expression,
        $.compound_expression,
        $.group,
        $.simple_expression,
        $._bool_lhs,
        $.in_expression,
      ),

    not_expression: ($) => prec(4, seq($.not_operator, $._expression)),

    in_expression: ($) => {
      const in_options = [
        [choice($.ip_field, $.ip_func), choice($.ip_set, $.list)],
        [
          choice($.stringlike_field, $.bytes_field),
          choice($.string_set, $.list),
        ],
        [$._number_lhs, choice($.number_set, $.list)],
      ];

      return choice(
        ...in_options.map(([field_type, target]) =>
          seq(
            field("lhs", field_type),
            field("operator", "in"),
            field("rhs", target),
          ),
        ),
      );
    },

    compound_expression: ($) => {
      const precs = [
        ["&&", 3],
        ["and", 3],
        ["xor", 2],
        ["^^", 2],
        ["or", 1],
        ["||", 1],
      ];

      return choice(
        ...precs.map(([operator, precedence]) =>
          prec.left(
            precedence,
            seq(
              field("lhs", $._expression),
              field("operator", operator),
              field("rhs", $._expression),
            ),
          ),
        ),
      );
    },

    ip_set: ($) => seq("{", repeat1(choice($._ip, $.ip_bounds)), "}"),

    string_set: ($) => seq("{", repeat1($.string), "}"),

    comment: ($) => token(seq("#", /.*/)),

    number_set: ($) => seq("{", repeat1(choice($.number, $.number_bounds)), "}"),

    // Inclusive `start..end` range. Valid only inside a `{ }` set.
    ip_bounds: ($) =>
      choice(
        seq(field("start", $.ipv4), "..", field("end", $.ipv4)),
        seq(field("start", $.ipv6), "..", field("end", $.ipv6)),
      ),

    number_bounds: ($) =>
      seq(field("start", $.number), "..", field("end", $.number)),

    simple_expression: ($) => {
      const comps = [
        [STRING_COMPARISON_OPS, $.stringlike_field, choice($.string, $.bytes)],
        [REGEX_OPS, $.stringlike_field, $.regex],
        [NUMBER_COMPARISON_OPS, $._number_lhs, $.number],
        [["eq", "ne", "==", "!="], choice($.ip_field, $.ip_func), $._ip],
        // IPs are ordered values in wirefilter: lt/le/gt/ge take a single IP.
        [
          ["lt", "le", "gt", "ge", "<", "<=", ">", ">="],
          choice($.ip_field, $.ip_func),
          choice($.ipv4, $.ipv6),
        ],
      ];

      return choice(
        ...comps.map(([operators, f, type]) =>
          seq(
            field("lhs", f),
            field("operator", choice(...operators)),
            field("rhs", type),
          ),
        ),
      );
    },

    _bool_lhs: ($) => choice($.boollike_field, $.boolean),

    _number_lhs: ($) => choice($.numberlike_field, $.number_func),

    // _string_lhs: ($) => choice($.stringlike_field, $.string_func),

    // functions grouped by return type for use in expressions
    string_func: ($) =>
      choice(
        concatFunc(
          choice($.string, $.stringlike_field),
          choice($.string, $.stringlike_field),
        ),
        lookupFunc($.stringlike_field, choice($.string, $.number)),
        lowerFunc($.stringlike_field),
        regexReplaceFunc($.stringlike_field, $.regex, $.string),
        removeBytesFunc(choice($.stringlike_field, $.bytes_field), $.string),
        toStringFunc(
          choice($.numberlike_field, $.ip_field, $.ip_func, $.boollike_field),
        ),
        upperFunc($.stringlike_field),
        urlDecodeFunc($.stringlike_field, $.string),
        uuidv4Func($.stringlike_field),
        decodeBase64Func($.stringlike_field),
        encodeBase64Func(
          choice($.string, $.stringlike_field, $.bytes_field),
          $.string,
        ),
        joinFunc($.string_array, $.string),
        removeQueryArgsFunc($.stringlike_field, $.string),
        sha256Func(choice($.string, $.stringlike_field, $.bytes_field)),
        substringFunc(choice($.stringlike_field, $.bytes_field), $.number),
        wildcardReplaceFunc(
          choice($.stringlike_field, $.bytes_field),
          $.string,
        ),
      ),

    number_func: ($) =>
      choice(
        lenFunc(choice($.stringlike_field, $.bytes_field)),
        bitSliceFunc(choice($.string, $.stringlike_field), $.number),
        lookupJsonIntegerFunc($.stringlike_field, choice($.string, $.number)),
      ),

    bool_func: ($) =>
      choice(
        $.array_func,
        endsWithFunc($.stringlike_field, $.string),
        startsWithFunc($.stringlike_field, $.string),
        isTimedHmacValidV0Func(
          $.string,
          $.stringlike_field,
          $.number,
          choice($.number, $.numberlike_field),
        ),
        hasKeyFunc($.map_string_array_field, $.string),
        hasValueFunc(
          choice($.map_string_array_field, $.array_string_field),
          choice($.string, $.number),
        ),
        isJwtPresentFunc($.string),
        isJwtValidFunc($.string),
      ),

    // IP-returning functions (cidr / cidr6).
    ip_func: ($) =>
      choice(
        cidrFunc(choice($.ip_field, $._ip), $.number),
        cidr6Func(choice($.ip_field, $._ip), $.number),
      ),

    array_func: ($) => {
      // Needs to support simple expressions and in and bool
      const in_func = [
        [arrayExpander($.number_array), $.number_set],
        [arrayExpander($.string_array), $.string_set],
      ];
      const inOptions = choice(
        ...in_func.map(([field_type, target]) =>
          seq(
            field("lhs", field_type),
            field("operator", "in"),
            field("rhs", target),
          ),
        ),
      );

      const simple = [
        [STRING_COMPARISON_OPS, arrayExpander($.string_array), $.string],
        [REGEX_OPS, arrayExpander($.string_array), $.regex],
        [NUMBER_COMPARISON_OPS, arrayExpander($.number_array), $.number],
      ];

      const simpleOptions = choice(
        ...simple.map(([operators, f, type]) =>
          seq(
            field("lhs", f),
            field("operator", choice(...operators)),
            field("rhs", type),
          ),
        ),
      );

      return seq(
        field("func", choice("any", "all")),
        "(",
        choice(simpleOptions, inOptions, arrayExpander($.bool_array)),
        ")",
      );
    },

    group: ($) => seq("(", field("inner", $._expression), ")"),

    number: ($) => /\d+/,

    // A byte-sequence literal: hex octet pairs separated by `:`, `-`, or `.`
    // (e.g. `6F:72:67`). A valid RHS for Bytes / String comparisons. Only
    // recognized in value position, so it does not shadow IPv4/IPv6 literals.
    bytes: ($) =>
      token(seq(/[0-9A-Fa-f]{2}/, repeat1(seq(/[.:-]/, /[0-9A-Fa-f]{2}/)))),

    // A double-quoted string value. Kept as a single leaf token so the parse
    // tree stays flat, but with correct escape handling: a backslash escapes
    // the following character, so `\"` and `\\` do not terminate the string,
    // and byte escapes such as `\xHH` / `\OOO` are accepted. Cloudflare's engine
    // (wirefilter) accepts ONLY double-quoted and raw strings — single quotes
    // are not a valid delimiter.
    // See: https://developers.cloudflare.com/ruleset-engine/rules-language/values/
    // A raw string (`r"..."`, `r#"..."#`, …) is an alternative form with no
    // escape processing, recognized by the external scanner (src/scanner.c).
    string: ($) => choice($._quoted_string, $.raw_string),

    // A regex value has the same lexical form as a string but is its own node
    // (used after `matches`/`~` and as the pattern of regex_replace) so editors
    // can inject a regex grammar into it — see queries/injections.scm.
    regex: ($) => choice($._quoted_string, $.raw_string),

    _quoted_string: ($) =>
      token(seq('"', repeat(choice(/[^"\\]/, /\\[\s\S]/)), '"')),

    boolean: ($) => choice("true", "false"),

    _ip: ($) => choice($.ipv4, $.ipv6, $.ip_range),

    ipv4: ($) =>
      /(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/,

    // Full RFC 5952 IPv6, including `::` compression and IPv4-mapped forms.
    // Written bare (no brackets, no quotes), e.g. `2001:db8::1`.
    ipv6: ($) => token(IPV6),

    // CIDR range for either family: IPv4 /0-32 or IPv6 /0-128.
    ip_range: ($) =>
      choice(
        seq(field("ip", $.ipv4), "/", field("mask", /(?:3[0-2]|[12]?[0-9])/)),
        seq(
          field("ip", $.ipv6),
          "/",
          field("mask", /(?:12[0-8]|1[01][0-9]|[0-9]?[0-9])/),
        ),
      ),

    // A named list reference. Custom lists (`$my_list`) and Cloudflare managed
    // lists (`$cf.anonymizer`, `$cf.open_proxies`, …) share the same dotted-name
    // form. Valid as the `in` RHS for IP, string/bytes, and number fields.
    list: ($) => token(seq("$", /[a-z\d_]+(\.[a-z\d_]+)*/)),

    not_operator: ($) => choice("not", "!"),

    number_array: ($) =>
      choice(
        $.array_number_field,
        seq($.map_number_array_field, "[", field("key", $.string), "]"),
        lenFunc($._string_array_expansion),
      ),

    bool_array: ($) =>
      choice(
        endsWithFunc($._string_array_expansion, $.string),
        startsWithFunc($._string_array_expansion, $.string),
      ),

    string_array: ($) =>
      choice(
        $.array_string_field,
        seq($.map_string_array_field, "[", field("key", $.string), "]"),
        concatFunc(
          $._string_array_expansion,
          choice($.string, $.stringlike_field),
        ),
        lookupFunc($._string_array_expansion, choice($.string, $.number)),
        lowerFunc($._string_array_expansion),
        regexReplaceFunc($._string_array_expansion, $.regex, $.string),
        removeBytesFunc($._string_array_expansion, $.string),
        toStringFunc(arrayExpander(choice($.number_array, $.bool_array))),
        upperFunc($._string_array_expansion),
        urlDecodeFunc($._string_array_expansion, $.string),
        uuidv4Func($._string_array_expansion),
        splitFunc(choice($.stringlike_field, $.string), $.string, $.number),
      ),

    _string_array_expansion: ($) =>
      arrayExpander(
        choice(
          seq($.map_string_array_field, "[", field("key", "*"), "]"),
          $.string_array,
        ),
      ),

    boollike_field: ($) =>
      choice(
        $.bool_field,
        seq($.bool_array, "[", field("index", $.number), "]"),
        $.bool_func,
        seq($.bool_func, "[", field("index", $.number), "]"),
      ),

    numberlike_field: ($) =>
      choice(
        $.number_field,
        seq($.number_array, "[", field("index", $.number), "]"),
        seq($.number_func, "[", field("index", $.number), "]"),
        // Map<Integer> keyed access, e.g. custom_topic_categories["Politics"].
        seq($.map_number_field, "[", field("key", $.string), "]"),
      ),

    stringlike_field: ($) =>
      choice(
        $.string_field,
        seq($.string_array, "[", field("index", $.number), "]"),
        $.string_func,
        seq($.string_func, "[", field("index", $.number), "]"),
      ),

    // Cloudflare Ruleset Fields
    // see: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/

    number_field: ($) =>
      choice(
        // Standard fields
        "http.request.timestamp.sec",
        "http.request.timestamp.msec",
        "ip.geoip.asnum",
        "ip.src.asnum",
        // Dynamic fields
        "cf.bot_management.score",
        "cf.edge.server_port",
        "cf.threat_score",
        "cf.waf.score",
        "cf.waf.score.sqli",
        "cf.waf.score.xss",
        "cf.waf.score.rce",
        // Magic Firewall fields
        "icmp.type",
        "icmp.code",
        "ip.hdr_len",
        "ip.len",
        "ip.opt.type",
        "ip.ttl",
        "tcp.flags",
        "tcp.srcport",
        "tcp.dstport",
        "udp.dstport",
        "udp.srcport",
        // HTTP request body fields
        "http.request.body.size",
        // HTTP response fields
        "http.response.code",
        "cf.response.1xxx_code",
        // TLS
        "cf.tls_client_hello_length",
        // LLM (Firewall for AI)
        "cf.llm.prompt.injection_score",
        "cf.llm.prompt.token_count",
        // Edge / timings
        "cf.edge.l4.delivery_rate",
        "cf.timings.edge_msec",
        "cf.timings.origin_ttfb_msec",
        "cf.timings.worker_msec",
        "cf.timings.client_tcp_rtt_msec",
        "cf.timings.client_quic_rtt_msec",
        // Magic Firewall
        "ip.dst.asnum",
      ),

    ip_field: ($) =>
      choice(
        // Standard fields
        "ip.src",
        // Dynamic fields
        "cf.edge.server_ip",
        // Magic Firewall fields
        "ip.dst",
      ),

    string_field: ($) =>
      choice(
        // Standard fields
        "http.cookie",
        "http.host",
        "http.referer",
        "http.request.full_uri",
        "http.request.method",
        "http.request.uri",
        "http.request.uri.path",
        "http.request.uri.path.extension",
        "http.request.uri.query",
        "http.user_agent",
        "http.request.version",
        "http.x_forwarded_for",
        "ip.src.lat",
        "ip.src.lon",
        "ip.src.city",
        "ip.src.postal_code",
        "ip.src.metro_code",
        "ip.src.region",
        "ip.src.region_code",
        "ip.src.timezone.name",
        "ip.geoip.continent",
        "ip.geoip.country",
        "ip.geoip.subdivision_1_iso_code",
        "ip.geoip.subdivision_2_iso_code",
        "ip.src.continent",
        "ip.src.country",
        "ip.src.subdivision_1_iso_code",
        "ip.src.subdivision_2_iso_code",
        "raw.http.request.full_uri",
        "raw.http.request.uri",
        "raw.http.request.uri.path",
        "raw.http.request.uri.query",
        // Dynamic fields
        "cf.bot_management.ja3_hash",
        "cf.verified_bot_category",
        "cf.hostname.metadata",
        "cf.worker.upstream_zone",
        // Magic Firewall fields
        "cf.colo.name",
        "cf.colo.region",
        "icmp",
        "ip",
        "ip.dst.country",
        "tcp",
        "udp",
        // HTTP request body fields
        "http.request.body.raw",
        "http.request.body.mime",
        // HTTP response fields
        "cf.response.error_type",
        "http.response.content_type.media_type",
        "raw.http.request.uri.path.extension",
        // TLS
        "cf.tls_version",
        "cf.tls_cipher",
        "cf.tls_client_random",
        "cf.tls_ciphers_sha1",
        "cf.tls_client_extensions_sha1",
        "cf.tls_client_extensions_sha1_le",
        "cf.bot_management.ja4",
        // mTLS client certificate
        "cf.tls_client_auth.cert_serial",
        "cf.tls_client_auth.cert_issuer_serial",
        "cf.tls_client_auth.cert_ski",
        "cf.tls_client_auth.cert_issuer_ski",
        "cf.tls_client_auth.cert_subject_dn",
        "cf.tls_client_auth.cert_subject_dn_legacy",
        "cf.tls_client_auth.cert_subject_dn_rfc2253",
        "cf.tls_client_auth.cert_issuer_dn",
        "cf.tls_client_auth.cert_issuer_dn_legacy",
        "cf.tls_client_auth.cert_issuer_dn_rfc2253",
        "cf.tls_client_auth.cert_not_before",
        "cf.tls_client_auth.cert_not_after",
        "cf.tls_client_auth.cert_fingerprint_sha1",
        "cf.tls_client_auth.cert_fingerprint_sha256",
        "cf.tls_client_auth.cert_rfc9440",
        "cf.tls_client_auth.cert_chain_rfc9440",
        // WAF
        "cf.waf.score.class",
        // Misc dynamic
        "cf.ray_id",
        // Magic Firewall
        "ip.proto",
      ),

    bytes_field: ($) => choice("cf.random_seed"),

    map_string_array_field: ($) =>
      choice(
        // Standard fields
        "http.request.cookies",
        // URI argument fields
        "http.request.uri.args",
        "raw.http.request.uri.args",
        // HTTP request header fields
        "http.request.headers",
        // HTTP request body fields
        "http.request.body.form",
        "http.request.body.multipart",
        // HTTP response fields
        "http.response.headers",
        "raw.http.response.headers",
        // JWT claims
        "http.request.jwt.claims.aud",
        "http.request.jwt.claims.iss",
        "http.request.jwt.claims.sub",
        "http.request.jwt.claims.jti",
      ),

    array_string_field: ($) =>
      choice(
        // URI argument fields
        "http.request.uri.args.names",
        "http.request.uri.args.values",
        "raw.http.request.uri.args.names",
        "raw.http.request.uri.args.values",
        // HTTP request header fields
        "http.request.headers.names",
        "http.request.headers.values",
        "http.request.accepted_languages",
        // HTTP request body fields
        "http.request.body.form.names",
        "http.request.body.form.values",
        // HTTP response fields
        "http.response.headers.names",
        "http.response.headers.values",
        "raw.http.response.headers.names",
        "raw.http.response.headers.values",
        // HTTP request body (multipart)
        "http.request.body.multipart.names",
        "http.request.body.multipart.values",
        "http.request.body.multipart.filenames",
        "http.request.body.multipart.content_types",
        "http.request.body.multipart.content_dispositions",
        "http.request.body.multipart.content_transfer_encodings",
        // JWT claims
        "http.request.jwt.claims.aud.names",
        "http.request.jwt.claims.aud.values",
        "http.request.jwt.claims.iss.names",
        "http.request.jwt.claims.iss.values",
        "http.request.jwt.claims.sub.names",
        "http.request.jwt.claims.sub.values",
        "http.request.jwt.claims.jti.names",
        "http.request.jwt.claims.jti.values",
        "http.request.jwt.claims.iat.sec.names",
        "http.request.jwt.claims.nbf.sec.names",
        // WAF content scan
        "cf.waf.content_scan.obj_results",
        "cf.waf.content_scan.obj_types",
        // LLM (Firewall for AI)
        "cf.llm.prompt.pii_categories",
        "cf.llm.prompt.unsafe_topic_categories",
      ),

    array_number_field: ($) =>
      choice(
        "cf.bot_management.detection_ids",
        "cf.waf.content_scan.obj_sizes",
        "http.request.jwt.claims.iat.sec.values",
        "http.request.jwt.claims.nbf.sec.values",
      ),

    // Map<Array<Integer>> — keyed by token-config id, yields an integer array.
    map_number_array_field: ($) =>
      choice(
        "http.request.jwt.claims.iat.sec",
        "http.request.jwt.claims.nbf.sec",
      ),

    // Map<Integer> — keyed by topic name, yields a scalar relevance score.
    map_number_field: ($) => choice("cf.llm.prompt.custom_topic_categories"),

    bool_field: ($) =>
      choice(
        // Standard fields
        "ip.geoip.is_in_european_union",
        "ip.src.is_in_european_union",
        "ssl",
        // Dynamic fields
        "cf.bot_management.verified_bot",
        "cf.bot_management.js_detection.passed",
        "cf.bot_management.corporate_proxy",
        "cf.bot_management.static_resource",
        "cf.client.bot",
        "cf.tls_client_auth.cert_revoked",
        "cf.tls_client_auth.cert_verified",
        // Magic Firewall fields
        "sip",
        "tcp.flags.ack",
        "tcp.flags.cwr",
        "tcp.flags.ecn",
        "tcp.flags.fin",
        "tcp.flags.push",
        "tcp.flags.reset",
        "tcp.flags.syn",
        "tcp.flags.urg",
        // HTTP request header fields
        "http.request.headers.truncated",
        // HTTP request body fields
        "http.request.body.truncated",
        // Bot management
        "cf.bot_management.signed_agent",
        // WAF
        "cf.waf.auth_detected",
        "cf.waf.content_scan.has_obj",
        "cf.waf.content_scan.has_malicious_obj",
        "cf.waf.content_scan.has_failed",
        "cf.waf.credential_check.password_leaked",
        "cf.waf.credential_check.username_leaked",
        "cf.waf.credential_check.username_and_password_leaked",
        "cf.waf.credential_check.username_password_similar",
        // LLM (Firewall for AI)
        "cf.llm.prompt.detected",
        "cf.llm.prompt.pii_detected",
        "cf.llm.prompt.unsafe_topic_detected",
        // API Gateway / schema validation
        "cf.api_gateway.auth_id_present",
        "cf.api_gateway.fallthrough_detected",
        "cf.api_gateway.request_violates_schema",
        // mTLS client certificate
        "cf.tls_client_auth.cert_presented",
        "cf.tls_client_auth.cert_rfc9440_too_large",
        "cf.tls_client_auth.cert_chain_rfc9440_too_large",
      ),
  },
});

// Cloudflare ruleset functions
// https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
// TODO(nfowl): Verify if functions can take raw values as well

// Caveats discovered via validation:
// - Concat takes minimum 2 args
// - Concat does not support numbers (TODO: chase this up)
function concatFunc(rule, args) {
  // concat takes a minimum of 2 args, comma-separated (trailing comma allowed).
  return seq(
    field("func", "concat"),
    "(",
    rule,
    ",",
    args,
    repeat(seq(",", args)),
    optional(","),
    ")",
  );
}

function endsWithFunc(rule, value) {
  return seq(
    field("func", "ends_with"),
    "(",
    field("field", rule),
    ",",
    field("value", value),
    ")",
  );
}

function lenFunc(rule) {
  return seq(field("func", "len"), "(", field("field", rule), ")");
}

function lookupFunc(rule, args) {
  // lookup_json_string(field, key1[, key2, ...]) — the field and each key are
  // comma-separated (trailing comma allowed).
  return seq(
    field("func", "lookup_json_string"),
    "(",
    field("field", rule),
    ",",
    field("keys", seq(args, repeat(seq(",", args)), optional(","))),
    ")",
  );
}

function lowerFunc(rule) {
  return seq(field("func", "lower"), "(", field("field", rule), ")");
}

function regexReplaceFunc(rule, regexArg, replacementArg) {
  return seq(
    field("func", "regex_replace"),
    "(",
    field("source", rule),
    ",",
    field("regex", regexArg),
    ",",
    field("replacement", replacementArg),
    ")",
  );
}

function removeBytesFunc(rule, value) {
  return seq(
    field("func", "remove_bytes"),
    "(",
    field("field", rule),
    ",",
    field("replacement", value),
    ")",
  );
}

function startsWithFunc(rule, value) {
  return seq(
    field("func", "starts_with"),
    "(",
    field("field", rule),
    ",",
    field("value", value),
    ")",
  );
}

function toStringFunc(rule) {
  return seq(field("func", "to_string"), "(", field("field", rule), ")");
}

function upperFunc(rule) {
  return seq(field("func", "upper"), "(", field("field", rule), ")");
}

function urlDecodeFunc(rule, options) {
  return seq(
    field("func", "url_decode"),
    "(",
    field("field", rule),
    optional(seq(",", field("options", options))),
    ")",
  );
}

function uuidv4Func(rule) {
  return seq(field("func", "uuidv4"), "(", field("seed", rule), ")");
}

// --- Functions added to match the current Cloudflare functions reference ---

function decodeBase64Func(rule) {
  return seq(field("func", "decode_base64"), "(", field("source", rule), ")");
}

function encodeBase64Func(rule, flags) {
  return seq(
    field("func", "encode_base64"),
    "(",
    field("input", rule),
    optional(seq(",", field("flags", flags))),
    ")",
  );
}

// join(values, separator) -> String
function joinFunc(arrayRule, separator) {
  return seq(
    field("func", "join"),
    "(",
    field("values", arrayRule),
    ",",
    field("separator", separator),
    ")",
  );
}

// remove_query_args(field, arg1[, arg2, ...]) -> String
function removeQueryArgsFunc(rule, arg) {
  return seq(
    field("func", "remove_query_args"),
    "(",
    field("field", rule),
    repeat1(seq(",", arg)),
    ")",
  );
}

function sha256Func(rule) {
  return seq(field("func", "sha256"), "(", field("input", rule), ")");
}

// substring(field, start[, end]) -> String
function substringFunc(rule, number) {
  return seq(
    field("func", "substring"),
    "(",
    field("field", rule),
    ",",
    field("start", number),
    optional(seq(",", field("end", number))),
    ")",
  );
}

// wildcard_replace(source, pattern, replacement[, flags]) -> String
function wildcardReplaceFunc(rule, value) {
  return seq(
    field("func", "wildcard_replace"),
    "(",
    field("source", rule),
    ",",
    field("pattern", value),
    ",",
    field("replacement", value),
    optional(seq(",", field("flags", value))),
    ")",
  );
}

// lookup_json_integer(field, key1[, key2, ...]) -> Integer
function lookupJsonIntegerFunc(rule, args) {
  return seq(
    field("func", "lookup_json_integer"),
    "(",
    field("field", rule),
    ",",
    field("keys", seq(args, repeat(seq(",", args)), optional(","))),
    ")",
  );
}

function hasKeyFunc(mapRule, key) {
  return seq(
    field("func", "has_key"),
    "(",
    field("map", mapRule),
    ",",
    field("key", key),
    ")",
  );
}

function hasValueFunc(collectionRule, value) {
  return seq(
    field("func", "has_value"),
    "(",
    field("collection", collectionRule),
    ",",
    field("value", value),
    ")",
  );
}

function isJwtPresentFunc(rule) {
  return seq(
    field("func", "is_jwt_present"),
    "(",
    field("token_configuration_id", rule),
    ")",
  );
}

function isJwtValidFunc(rule) {
  return seq(
    field("func", "is_jwt_valid"),
    "(",
    field("token_configuration_id", rule),
    ")",
  );
}

// cidr(address, ipv4_bits, ipv6_bits) -> IP
function cidrFunc(address, number) {
  return seq(
    field("func", "cidr"),
    "(",
    field("address", address),
    ",",
    field("ipv4_bits", number),
    ",",
    field("ipv6_bits", number),
    ")",
  );
}

// cidr6(address, ipv6_bits) -> IP
function cidr6Func(address, number) {
  return seq(
    field("func", "cidr6"),
    "(",
    field("address", address),
    ",",
    field("ipv6_bits", number),
    ")",
  );
}

// split(input, separator, limit) -> Array<String>
function splitFunc(rule, separator, number) {
  return seq(
    field("func", "split"),
    "(",
    field("input", rule),
    ",",
    field("separator", separator),
    ",",
    field("limit", number),
    ")",
  );
}

// bit_slice(protocol, offset_start, offset_end) -> Number
// Extracts a slice of bits from a protocol header (Magic Firewall).
// e.g. bit_slice("udp", 64, 80)
function bitSliceFunc(protocol, number) {
  return seq(
    field("func", "bit_slice"),
    "(",
    field("protocol", protocol),
    ",",
    field("offset_start", number),
    ",",
    field("offset_end", number),
    ")",
  );
}

// is_timed_hmac_valid_v0(key, message_mac, ttl, current_timestamp,
//                        [separator_length], [flags]) -> Boolean
// e.g. is_timed_hmac_valid_v0("secret", http.request.uri, 100000,
//                             http.request.timestamp.sec, 8, "s")
function isTimedHmacValidV0Func(str, macField, number, timestamp) {
  return seq(
    field("func", "is_timed_hmac_valid_v0"),
    "(",
    field("key", str),
    ",",
    field("message", macField),
    ",",
    field("ttl", number),
    ",",
    field("timestamp", timestamp),
    // `flags` is only valid when `separator_length` is present, so the two
    // optional trailing args nest rather than standing as independent siblings.
    optional(
      seq(
        ",",
        field("separator_length", number),
        optional(seq(",", field("flags", str))),
      ),
    ),
    ")",
  );
}

function arrayExpander(rule) {
  return seq(rule, "[*]");
}
