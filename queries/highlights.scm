(string) @string
(number) @number
(boolean) @boolean
(comment) @comment
(ERROR) @error

[
  (string_func)
  (bool_func)
  (number_func)
] @function

[
  (ip_range)
  (ipv4)
  (ipv6)
  (ip_list)
] @variable

[
 (number_field)
 (ip_field)
 (string_field)
 (bool_field)
 (bytes_field)
 (array_string_field)
 (array_number_field)
 (map_string_array_field)
] @type

[
  "not"
  "!"
  "and"
  "&&"
  "or"
  "||"
  "xor"
  "^^"
  "eq"
  "=="
  "ne"
  "!="
  "lt"
  "<"
  "le"
  "<="
  "gt"
  ">"
  "ge"
  ">="
  "contains"
  "matches"
  "~"
  "wildcard"
  "strict wildcard"
  "in"
] @operator

[
  "{"
  "}"
  "("
  ")"
  "["
  "]"
] @punctuation.bracket
