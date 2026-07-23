; Inject a regex grammar into regex operands (the RHS of `matches` / `~` and the
; pattern argument of regex_replace), so editors highlight them as regexes.
((regex) @injection.content
 (#set! injection.language "regex"))
