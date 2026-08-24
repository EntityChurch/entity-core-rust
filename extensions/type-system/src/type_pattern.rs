//! `type_pattern` constraint matching (EXTENSION-TYPE §4.6).
//!
//! **This is not a glob, and the module that used to say so was the bug.**
//! §4.6 `[v1.2]` pins the matcher to `ENTITY-CORE-PROTOCOL` §5.4
//! `matches_pattern` — *"the protocol's single pattern rule, applied here to
//! the entity's **type name** rather than to a tree path"* — which admits
//! exactly three forms:
//!
//! - bare `*` — matches any type;
//! - `<lit>/*` — **subtree prefix**, so `system/capability/*` matches
//!   `system/capability/grant-entry` **and** `system/capability/path-scope/foo`;
//! - anything else — exact.
//!
//! *"There is no segment-scoped wildcard and no `**`."* The prior
//! implementation here was a conventional path-glob: `*` stopped at `/` and
//! `**` / `**​/` crossed segments. Both readings answer
//! `system/capability/*` vs `system/capability/path-scope/foo` — the example
//! §4.6 spells out — with **opposite** results, and nothing failed anywhere:
//! a `type_pattern` constraint is a validation verdict, so the divergence
//! surfaces as one peer accepting an entity another rejects.
//!
//! Delegating rather than reimplementing is deliberate. A second matcher that
//! *happens* to agree today is the shape core-go's matcher-convergence finding
//! names: two matchers in one tree silently disagreeing on `a/b/*` vs bare
//! `a/b`. There is one §5.4 matcher in this workspace and this calls it.

/// Match an entity **type name** against a §4.6 `type_pattern`.
///
/// Type names carry no leading `/` and no peer segment, so §5.4's `/*/`
/// peer-wildcard form has nothing to bind to and simply never fires; the
/// remaining three forms are the whole of §4.6's vocabulary.
pub fn type_pattern_matches(pattern: &str, type_name: &str) -> bool {
    entity_capability::matches_pattern(type_name, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        assert!(type_pattern_matches("foo/bar", "foo/bar"));
        assert!(!type_pattern_matches("foo/bar", "foo/baz"));
    }

    #[test]
    fn match_all() {
        assert!(type_pattern_matches("*", "anything"));
        assert!(type_pattern_matches("*", "system/capability/grant-entry"));
    }

    /// §4.6's own worked example, and the row the previous segment-scoped
    /// matcher got backwards: `pattern/*` is a **subtree prefix match**, so it
    /// reaches any depth below the prefix.
    #[test]
    fn subtree_prefix_crosses_segments() {
        assert!(type_pattern_matches(
            "system/capability/*",
            "system/capability/grant-entry"
        ));
        assert!(type_pattern_matches(
            "system/capability/*",
            "system/capability/path-scope/foo"
        ));
        // The retained `/` blocks the sibling-prefix false positive.
        assert!(!type_pattern_matches(
            "system/capability/*",
            "system/capabilityx/foo"
        ));
        // Prefix alone is not below itself.
        assert!(!type_pattern_matches(
            "system/capability/*",
            "system/capability"
        ));
    }

    /// The three forms are closed: a `*` anywhere else is a literal byte, not
    /// a wildcard. Each of these matched under the old glob and MUST NOT now.
    #[test]
    fn no_segment_wildcard_and_no_globstar() {
        // Interior `*` — was a segment wildcard.
        assert!(!type_pattern_matches("foo/*/bar", "foo/x/bar"));
        // Leading `*` — was "any chars within one segment".
        assert!(!type_pattern_matches("*bar", "foobar"));
        assert!(!type_pattern_matches("foo*", "foobar"));
        // `**` — was a globstar.
        assert!(!type_pattern_matches("system/**", "system/x"));
        assert!(!type_pattern_matches("**/foo", "a/b/c/foo"));
        assert!(!type_pattern_matches("a/**/b", "a/x/y/b"));
        // …and each is an ordinary literal, so it still matches itself.
        assert!(type_pattern_matches("foo/*/bar", "foo/*/bar"));
        assert!(type_pattern_matches("a/**/b", "a/**/b"));
    }
}
