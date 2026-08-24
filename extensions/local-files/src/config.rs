//! Root mapping configuration, path translation, and glob filters
//! (DOMAIN-LOCAL-FILES §2.5, §8).

use std::path::{Component, Path, PathBuf};

use crate::types::RootConfigData;

/// In-memory root mapping. The handler holds a name → `RootMapping` map.
#[derive(Debug, Clone)]
pub struct RootMapping {
    pub name: String,
    /// Tree prefix (e.g., `"local/files/shared/"`). Always ends with `/`.
    pub prefix: String,
    /// Filesystem root, canonicalized when possible (e.g., `/home/alice/shared`).
    pub fs_root: PathBuf,
    pub read_only: bool,
    pub exclude: Vec<String>,
    pub include: Vec<String>,
    pub publish_descriptors: bool,
}

impl RootMapping {
    pub fn from_config(name: String, cfg: &RootConfigData) -> Result<Self, String> {
        let mut prefix = cfg.prefix.clone();
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let fs_root_path = Path::new(&cfg.filesystem_root);
        let fs_root = fs_root_path.canonicalize().unwrap_or_else(|_| {
            // Root may not exist yet; absolutize without canonicalizing.
            if fs_root_path.is_absolute() {
                fs_root_path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map(|c| c.join(fs_root_path))
                    .unwrap_or_else(|_| fs_root_path.to_path_buf())
            }
        });
        Ok(RootMapping {
            name,
            prefix,
            fs_root,
            read_only: cfg.read_only,
            exclude: cfg.exclude.clone(),
            include: cfg.include.clone(),
            publish_descriptors: cfg.publish_descriptors,
        })
    }
}

/// Resolve a tree path inside a root mapping to (filesystem_path,
/// relative_path).
///
/// Applies both v1.3 §8.3 defenses:
///
/// 1. **Parent-traversal MUST.** Reject `..` segments in the input path
///    (closes the `local/files/shared/../etc/passwd` exploit).
/// 2. **Leaf-symlink MUST (interim).** `lstat` the resolved target; if
///    it's a symlink, reject with `path_traversal_rejected`. This is the
///    spec-pinned interim mitigation per §8.3 — it closes the trivial
///    leaf-symlink exploit at the cost of a narrow TOCTOU window
///    between the lstat and the subsequent open. The kernel-enforced
///    fix (`cap-std` / `openat2(RESOLVE_BENEATH)`) is scheduled as the
///    second-pass migration; until then this is the conformant
///    interim defense per §8.3.
///
/// **Per §8.3 callsite MUST: every callsite that resolves a tree path to
/// a filesystem path uses this function** — read, write, list, delete,
/// reverse-write, reverse-delete, watcher debounce-flush. Go's L5 audit
/// (commit `ba21372`) found their reverse-* paths bypassing the
/// canonical resolver; Rust has the same shape and the fix is to route
/// those callsites here.
pub fn resolve_fs_path(root: &RootMapping, tree_path: &str) -> Result<(PathBuf, String), String> {
    let relative = tree_path
        .strip_prefix(&root.prefix)
        .ok_or_else(|| "tree path does not start with root prefix".to_string())?;
    if !is_safe_relative(relative) {
        return Err(format!("path traversal rejected: {tree_path}"));
    }
    let fs_path = root.fs_root.join(relative);
    reject_if_symlink_on_path(&root.fs_root, relative)?;
    Ok((fs_path, relative.to_string()))
}

/// Same as `resolve_fs_path` but takes a relative path directly. Used by
/// watcher and reverse-write paths that already have the relative path
/// in hand (from notify event stripping or tree-event prefix-trim).
pub fn resolve_fs_path_relative(root: &RootMapping, relative: &str) -> Result<PathBuf, String> {
    if !is_safe_relative(relative) {
        return Err(format!("path traversal rejected: {relative}"));
    }
    let fs_path = root.fs_root.join(relative);
    reject_if_symlink_on_path(&root.fs_root, relative)?;
    Ok(fs_path)
}

/// Leaf-symlink rejection per v1.3 §8.3 (interim non-atomic form).
///
/// Reject any target whose final component is a symlink. Existing-file
/// case: lstat says symlink → reject. New-file case: lstat returns
/// NotFound → accept (we're about to create the file, no symlink yet).
/// Any other lstat error surfaces as a path traversal error to be safe.
///
/// TOCTOU: there is a window between this check and the caller's open.
/// An attacker with concurrent write access to the parent dir could
/// race in a symlink. The spec acknowledges this as the price of the
/// interim form (§8.3); `cap-std`'s `openat2(RESOLVE_BENEATH)` is the
/// kernel-enforced fix scheduled as the second-pass migration.
pub fn reject_if_leaf_symlink(fs_path: &Path) -> Result<(), String> {
    // Strip trailing separators before the lstat. POSIX gives a trailing
    // slash the meaning "this component IS a directory", and the kernel
    // implements that by RESOLVING a final symlink — so `lstat("link/")`
    // returns the metadata of the target directory and reports
    // `is_symlink() == false`, while `lstat("link")` reports the link.
    //
    // That is not a detail: `list` normalizes its tree path to end in `/`
    // before resolving, so without this trim the defense inspected the
    // wrong inode and a symlinked DIRECTORY planted in the root was
    // enumerated straight through — `read_dir` follows the link and
    // returns the outside directory's contents at 200. A leaf-symlink
    // check that only ever saw file leaves passed for exactly as long as
    // nobody pointed a directory-shaped op at it (§8.3 V4a).
    let probe = trim_trailing_separators(fs_path);
    match std::fs::symlink_metadata(&probe) {
        Ok(md) if md.file_type().is_symlink() => Err(format!(
            "path traversal rejected: leaf is a symlink: {}",
            probe.display()
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("path resolution failed: {e}")),
    }
}

/// Reject a symlink at **any** component of `relative` beneath `fs_root`, not
/// only at the leaf (v1.3 §8.3 containment).
///
/// A leaf-only check answers "is the thing I am about to open a link?" — but
/// escaping does not require the leaf to be the link. Plant `escape-dir` as a
/// symlink to somewhere outside and ask for `escape-dir/secret.txt`: the leaf
/// is a perfectly ordinary file, so a leaf-only defense admits it, and the
/// open then walks out of the sandbox through the intermediate component. The
/// only inode a leaf check never inspects is the one doing the escaping.
///
/// So walk down from the root and `lstat` each component. Every path examined
/// is inside the root by construction (`is_safe_relative` has already rejected
/// `..`), and the walk stops at the first component that does not exist —
/// which is the create-a-new-file case, and is why `write` to a fresh path
/// still works.
///
/// This remains the **interim, non-atomic** form §8.3 sanctions: the TOCTOU
/// window between these `lstat`s and the caller's `open` is unchanged, and
/// `cap-std` / `openat2(RESOLVE_BENEATH)` is still the kernel-enforced fix
/// scheduled as the second-pass migration. What changes is which escapes the
/// interim form actually catches.
pub fn reject_if_symlink_on_path(fs_root: &Path, relative: &str) -> Result<(), String> {
    let mut current = fs_root.to_path_buf();
    for component in relative.split('/').filter(|c| !c.is_empty()) {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(format!(
                    "path traversal rejected: symlink on path: {}",
                    current.display()
                ))
            }
            Ok(_) => {}
            // Nothing here yet — nothing below it either, so there is no
            // further component that could be a link. `write` creating a new
            // file lands here.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("path resolution failed: {e}")),
        }
    }
    Ok(())
}

/// Drop trailing `/` from a path so `lstat` reports the leaf itself rather
/// than following it. The filesystem root (`/`) is returned unchanged — it
/// is all separator, and it is never a symlink.
fn trim_trailing_separators(fs_path: &Path) -> PathBuf {
    let s = fs_path.as_os_str().to_string_lossy();
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() {
        return fs_path.to_path_buf();
    }
    PathBuf::from(trimmed)
}

/// True if `rel` has no `..` segments and stays within the root logically.
/// Defense in depth — `resolve_fs_path` also checks that the canonicalized
/// result stays under the root for the lookup-path case.
fn is_safe_relative(rel: &str) -> bool {
    let p = Path::new(rel);
    for c in p.components() {
        match c {
            Component::ParentDir => return false,
            Component::RootDir | Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

/// True if `name` matches any of the exclude patterns (filename glob match
/// via `glob::Pattern`, identical wire semantics to Go's `filepath.Match`).
pub fn matches_exclude(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        glob::Pattern::new(p)
            .map(|pat| pat.matches(name))
            .unwrap_or(false)
    })
}

/// True if `name` passes the include filter. Empty include = pass through
/// (no positive filter). Non-empty = must match at least one pattern.
pub fn matches_include(name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|p| {
        glob::Pattern::new(p)
            .map(|pat| pat.matches(name))
            .unwrap_or(false)
    })
}

/// Combined file-admission check (§2.5 admission rule).
pub fn file_skipped(name: &str, exclude: &[String], include: &[String]) -> bool {
    if matches_exclude(name, exclude) {
        return true;
    }
    !matches_include(name, include)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(prefix: &str, fs_root: &str) -> RootMapping {
        RootMapping {
            name: "test".to_string(),
            prefix: prefix.to_string(),
            fs_root: PathBuf::from(fs_root),
            read_only: false,
            exclude: vec![],
            include: vec![],
            publish_descriptors: false,
        }
    }

    #[test]
    fn resolve_basic() {
        let r = root("local/files/shared/", "/tmp/shared");
        let (fs, rel) = resolve_fs_path(&r, "local/files/shared/readme.md").unwrap();
        assert_eq!(rel, "readme.md");
        assert_eq!(fs, PathBuf::from("/tmp/shared/readme.md"));
    }

    #[test]
    fn resolve_rejects_dot_dot() {
        let r = root("local/files/shared/", "/tmp/shared");
        let err = resolve_fs_path(&r, "local/files/shared/../etc/passwd").unwrap_err();
        assert!(err.contains("path traversal"));
    }

    /// `LF-CONTAIN-BOUNDARY-1` (DOMAIN-LOCAL-FILES §8.3) — a containment
    /// prefix test MUST break on a component boundary. core-go's had none, so
    /// a root at `/srv/peerroot` contained `/srv/peerroot-backup`; arch took
    /// the spec defect as theirs (§8.3's own pseudocode read as a raw string
    /// prefix test) and restructured the section with this as its own MUST.
    ///
    /// **Rust is not exposed, and the reason is worth pinning rather than
    /// re-deriving.** Two separate mechanisms carry the boundary, neither of
    /// them an explicit boundary check:
    ///
    /// 1. **Tree side** — [`RootMapping::from_config`] normalizes `prefix` to
    ///    always end in `/`, so the separator is *inside* the needle and
    ///    `str::strip_prefix` cannot match a sibling whose name merely starts
    ///    with the root's. This test drives `from_config` rather than the
    ///    `root()` helper, because the helper takes the prefix verbatim and
    ///    would assert the invariant into existence instead of checking it.
    /// 2. **Filesystem side** — `watcher.rs` compares with
    ///    `Path::strip_prefix`, which is component-aware by construction
    ///    (`/srv/peerroot-backup/x` does not strip `/srv/peerroot`), unlike the
    ///    `str` method of the same name. Asserted below so a "simplification"
    ///    to string comparison fails here.
    ///
    /// The V4 probe is read-only and structurally cannot reach either — "V4a
    /// green is not containment audited" is normative. This is the read.
    #[test]
    fn containment_prefix_breaks_on_a_component_boundary() {
        let cfg = RootConfigData {
            prefix: "local/files/shared".to_string(), // no trailing slash
            filesystem_root: "/tmp/shared".to_string(),
            ..Default::default()
        };
        let r = RootMapping::from_config("test".into(), &cfg).unwrap();
        assert_eq!(
            r.prefix, "local/files/shared/",
            "prefix is boundary-normalized"
        );

        // The sibling root whose name starts with ours is NOT contained.
        assert!(
            resolve_fs_path(&r, "local/files/shared-backup/secret").is_err(),
            "a sibling prefix sharing our leading characters resolved as ours"
        );
        // ...while the genuine child still resolves.
        let (_fs, rel) = resolve_fs_path(&r, "local/files/shared/readme.md").unwrap();
        assert_eq!(rel, "readme.md");

        // Filesystem side: component-aware, not textual.
        assert!(
            Path::new("/srv/peerroot-backup/x")
                .strip_prefix(Path::new("/srv/peerroot"))
                .is_err(),
            "fs containment must break on a component boundary"
        );
        assert!(Path::new("/srv/peerroot/x")
            .strip_prefix(Path::new("/srv/peerroot"))
            .is_ok());
    }

    #[test]
    fn exclude_matches_glob() {
        let pats = vec!["*.tmp".to_string(), ".git".to_string()];
        assert!(matches_exclude("foo.tmp", &pats));
        assert!(matches_exclude(".git", &pats));
        assert!(!matches_exclude("readme.md", &pats));
    }

    #[test]
    fn include_empty_passes_all() {
        let pats: Vec<String> = vec![];
        assert!(matches_include("foo.md", &pats));
        assert!(matches_include("anything", &pats));
    }

    #[test]
    fn include_non_empty_filters() {
        let pats = vec!["*.md".to_string()];
        assert!(matches_include("readme.md", &pats));
        assert!(!matches_include("readme.txt", &pats));
    }
}
