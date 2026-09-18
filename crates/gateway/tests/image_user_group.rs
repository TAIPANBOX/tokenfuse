//! The runtime user of every image has the group its uid implies
//! (tokenfuse#292).
//!
//! Measured 2026-09-17 on the appliance proving run: both images created
//! their user with `useradd -r -u 10001 tokenfuse` and nothing else, and on
//! Debian a system user created that way gets a private group from the
//! SYSTEM gid range, not one matching its uid. `id` inside the container read
//! `uid=10001 gid=999`. The launchers share their events directory as
//! `root:10001 2775`, so a process in gid 999 cannot create a file in it, and
//! the Cloud's export silently did nothing (the other half of that issue is
//! the silence, held by `crates/cloud/tests/events_export_startup.rs`).
//!
//! Text, not a build: CI's `fmt · clippy · test` job builds no image, and the
//! image job runs on tags only. What can be held here is that every
//! Dockerfile creating uid 10001 creates gid 10001 first and puts the user in
//! it. The subjects are DISCOVERED by walking the repository for files named
//! `Dockerfile*`, never listed, so an image added later is checked too, and a
//! walk that finds no such file panics as having measured nothing.

use std::path::{Path, PathBuf};

/// Every `Dockerfile*` under the repository root, skipping build output and
/// vendored trees.
fn dockerfiles(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "target" | "node_modules" | ".git" | ".venv") {
                continue;
            }
            dockerfiles(&path, out);
        } else if name.starts_with("Dockerfile") {
            out.push(path);
        }
    }
}

/// The `useradd` and `groupadd` invocations in a Dockerfile, in order, each
/// as its own argument list. Lines are joined across `\` continuations first
/// and split on `&&`, so `RUN a \ && b` reads as two commands.
fn user_and_group_commands(text: &str) -> Vec<Vec<String>> {
    let joined = text.replace("\\\n", " ");
    joined
        .lines()
        .flat_map(|line| line.split("&&").map(str::to_string).collect::<Vec<_>>())
        .map(|cmd| {
            cmd.split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|argv| {
            argv.first()
                .is_some_and(|a| a == "useradd" || a == "groupadd")
        })
        .collect()
}

/// The value following `flag` in an argument list (`-u 10001`), if any.
fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .map(String::as_str)
}

/// RED-FIRST: both Dockerfiles ran `useradd -r -u 10001 tokenfuse` with no
/// `groupadd` before it and no `-g`, so this failed naming each of them.
#[test]
fn every_image_that_creates_uid_10001_creates_group_10001_first_and_puts_the_user_in_it() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root");
    let mut files = Vec::new();
    dockerfiles(&root, &mut files);
    files.sort();

    let mut creating_10001 = 0;
    let mut faults = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable Dockerfile");
        let commands = user_and_group_commands(&text);
        let rel = file.strip_prefix(&root).unwrap_or(file).display();
        for (i, argv) in commands.iter().enumerate() {
            if argv[0] != "useradd" || flag_value(argv, "-u") != Some("10001") {
                continue;
            }
            creating_10001 += 1;
            let group_first = commands[..i]
                .iter()
                .any(|g| g[0] == "groupadd" && flag_value(g, "-g") == Some("10001"));
            if !group_first {
                faults.push(format!(
                    "{rel}: `{}` has no `groupadd -g 10001` before it, so the user's \
                     group is whatever gid the system range hands out (999 on Debian)",
                    argv.join(" ")
                ));
            }
            if flag_value(argv, "-g") != Some("10001") {
                faults.push(format!(
                    "{rel}: `{}` does not put the user in gid 10001 (`-g 10001`)",
                    argv.join(" ")
                ));
            }
        }
    }

    assert!(
        creating_10001 > 0,
        "measured nothing: no Dockerfile under {} creates uid 10001; the walk saw {:?}",
        root.display(),
        files
    );
    assert!(
        faults.is_empty(),
        "an image runs as 10001 with a gid other than 10001, which is the fault the \
         2026-09-17 appliance run measured as `uid=10001 gid=999` against a \
         `root:10001 2775` events directory:\n  {}",
        faults.join("\n  ")
    );
}
