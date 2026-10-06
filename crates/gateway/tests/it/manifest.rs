//! The declaration in `components.json` is only worth reading if this repository
//! proves it, and proves it against the toolchain rather than by describing.
//!
//! estate-gates cannot do this. It has no Rust toolchain, and building
//! twenty-two repositories in its CI is a matrix it does not have. This
//! repository already runs `cargo test` on every push.
//!
//! What is proved here is exactly the `checked` bucket and nothing else. The
//! `declared` bucket is not asserted against anything, on purpose: a test that
//! pretended to verify a sentence about purpose would be the failure this whole
//! design exists to avoid.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The repository root. `CARGO_MANIFEST_DIR` is `crates/gateway`.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/gateway has two ancestors")
        .to_path_buf()
}

fn manifest() -> Value {
    let path = root().join("components.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("components.json is valid JSON")
}

fn components(m: &Value) -> Vec<&Value> {
    let cs = m["components"].as_array().expect("components is an array");
    assert!(
        !cs.is_empty(),
        "components.json declares nothing, so every test here measured nothing"
    );
    cs.iter().collect()
}

/// Every `[[bin]]` a workspace builds, by `cargo metadata`.
///
/// The `--manifest-path` argument is the whole point of this helper. `cargo
/// metadata` at the root reports two binaries and stops, because
/// `crates/cluster` is a SEPARATE workspace. That is the same seam the
/// two-lockfile trap sits in, which CLAUDE.md already records for `cargo audit`.
fn binaries(workspace: &str) -> BTreeSet<String> {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["metadata", "--no-deps", "--format-version", "1"]);
    let manifest_path = root().join(workspace).join("Cargo.toml");
    cmd.arg("--manifest-path").arg(&manifest_path);
    let out = cmd.output().expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata for {}: {}",
        manifest_path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).expect("cargo metadata is JSON");
    let mut found = BTreeSet::new();
    for p in meta["packages"].as_array().expect("packages") {
        for t in p["targets"].as_array().expect("targets") {
            let is_bin = t["kind"]
                .as_array()
                .expect("kind")
                .iter()
                .any(|k| k == "bin");
            if is_bin {
                found.insert(t["name"].as_str().expect("target name").to_string());
            }
        }
    }
    found
}

/// THE ONE THAT CLOSES THE HOLE, and the one that found something.
///
/// estate.json says this repository runs three things and the workspaces build
/// three binaries, and they are not the same three: `focus-export` is a
/// subcommand, and `tokenfuse-cluster` lives in a workspace the registry has
/// never heard of.
#[test]
fn every_binary_these_workspaces_build_is_declared_and_the_reverse() {
    let m = manifest();
    let comps = components(&m);

    // Every workspace any component names, so adding a third one to the manifest
    // brings it into this check without editing the check.
    let mut workspaces: BTreeSet<String> = BTreeSet::new();
    for c in &comps {
        let w = c["checked"]["workspace"]
            .as_str()
            .unwrap_or_else(|| panic!("component {} declares no workspace", c["name"]));
        workspaces.insert(w.to_string());
    }
    assert!(
        !workspaces.is_empty(),
        "no component names a workspace, so this measured nothing"
    );

    let mut built: BTreeMap<String, String> = BTreeMap::new();
    for w in &workspaces {
        for b in binaries(w) {
            built.insert(b, w.clone());
        }
    }
    assert!(
        !built.is_empty(),
        "cargo metadata found no binary in {workspaces:?}, so this measured nothing"
    );

    let declared: BTreeSet<String> = comps
        .iter()
        .filter_map(|c| c["checked"]["binary"].as_str().map(str::to_string))
        .collect();
    assert!(
        !declared.is_empty(),
        "no component declares a binary, so this measured nothing"
    );

    for (b, w) in &built {
        assert!(
            declared.contains(b),
            "the {w} workspace builds `{b}` and components.json does not declare it.\n\
             A component nobody declares is one no deployment can be asked to install."
        );
    }
    for b in &declared {
        assert!(
            built.contains_key(b),
            "components.json declares the binary `{b}` and no workspace builds it"
        );
    }

    // And the workspace each component names is the one that actually builds it,
    // which is what makes `crates/cluster` visible rather than merely listed.
    for c in &comps {
        let (Some(b), Some(w)) = (
            c["checked"]["binary"].as_str(),
            c["checked"]["workspace"].as_str(),
        ) else {
            continue;
        };
        assert_eq!(
            built.get(b).map(String::as_str),
            Some(w),
            "components.json says `{b}` is built by the {w} workspace; cargo says {:?}",
            built.get(b)
        );
    }
}

/// Every `TOKENFUSE_` name in non-test source against the UNION of what the
/// components declare.
///
/// The split across components is organisational and by prefix, since the
/// gateway, its MCP surface and the cloud share a prefix space and assigning
/// each of a hundred names to its reader would be guesswork. So a name moving
/// between components does not fail here; a name appearing or disappearing does.
///
/// A name ending in `_` is a prefix fragment from a doc comment, not a variable.
#[test]
fn every_environment_variable_this_repository_reads_is_declared_and_the_reverse() {
    let m = manifest();
    let comps = components(&m);

    let mut declared: BTreeSet<String> = BTreeSet::new();
    for c in &comps {
        if let Some(env) = c["checked"]["env"].as_object() {
            declared.extend(env.keys().cloned());
        }
    }
    assert!(
        !declared.is_empty(),
        "no component declares an environment variable, so this measured nothing"
    );

    let mut in_source: BTreeSet<String> = BTreeSet::new();
    walk(&root(), &mut |p: &Path| {
        let s = p.to_string_lossy();
        if !s.ends_with(".rs") || s.contains("/target/") || s.contains("/tests/") {
            return;
        }
        let Ok(body) = std::fs::read_to_string(p) else {
            return;
        };
        for name in names_in(&body) {
            if !name.ends_with('_') {
                in_source.insert(name);
            }
        }
    });
    assert!(
        !in_source.is_empty(),
        "no TOKENFUSE_ name found in any non-test .rs file, so this measured nothing"
    );

    let missing: Vec<_> = in_source.difference(&declared).cloned().collect();
    let extra: Vec<_> = declared.difference(&in_source).cloned().collect();
    assert!(
        missing.is_empty(),
        "the code reads these and components.json declares none of them: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "components.json declares these and no non-test source reads them: {extra:?}"
    );
}

/// The declared listen default is the string the binary falls back to.
#[test]
fn the_declared_listen_default_is_the_one_the_code_uses() {
    let m = manifest();
    let main = std::fs::read_to_string(root().join("crates/gateway/src/main.rs"))
        .expect("reading the gateway's main.rs");

    let mut checked = 0;
    for c in components(&m) {
        let Some(want) = c["checked"]["listen_default"].as_str() else {
            continue;
        };
        checked += 1;
        let needle = format!("\"TOKENFUSE_ADDR\").unwrap_or_else(|_| \"{want}\".to_string())");
        assert!(
            main.contains(&needle),
            "components.json says the default listen address is {want:?} and \
             main.rs does not fall back to it"
        );
    }
    assert!(
        checked > 0,
        "no component declares a listen default, so this measured nothing"
    );
}

/// A declared subcommand is one the binary actually dispatches on.
#[test]
fn every_declared_subcommand_is_one_the_binary_dispatches_on() {
    let m = manifest();
    let main = std::fs::read_to_string(root().join("crates/gateway/src/main.rs"))
        .expect("reading the gateway's main.rs");

    let mut checked = 0;
    for c in components(&m) {
        let Some(sub) = c["checked"]["subcommand"].as_str() else {
            continue;
        };
        checked += 1;
        assert!(
            main.contains(&format!("\"{sub}\"")),
            "components.json says {} runs `tokenfuse {sub}` and main.rs never mentions it",
            c["name"]
        );
    }
    assert!(
        checked > 0,
        "no component declares a subcommand, so this measured nothing"
    );
}

fn names_in(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let needle = b"TOKENFUSE_";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            while j < bytes.len()
                && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit() || bytes[j] == b'_')
            {
                j += 1;
            }
            out.push(String::from_utf8_lossy(&bytes[i..j]).into_owned());
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn walk(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if p.is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&p, f);
        } else {
            f(&p);
        }
    }
}
