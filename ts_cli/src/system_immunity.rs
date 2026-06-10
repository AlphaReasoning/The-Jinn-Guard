//! System-process immunity rules for non-destructive enforcement failover.
//!
//! This module is userspace-only. It centralizes base-system allow rules so
//! the daemon, MCP gateway, and eBPF map loader agree on what must remain
//! administrable during active enforcement.

use crate::governance::{ObservationRecord, ProposedAction};
use std::collections::HashSet;
use std::path::Path;

pub const IMMUNE_PROCESS_NAMES: &[&str] = &[
    "systemd", "lightdm", "Xorg", "getty", "sh", "dash", "bash", "cargo",
];

pub const IMMUNE_EXACT_PATHS: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/systemctl",
    "/usr/bin/journalctl",
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/dash",
    "/usr/bin/dash",
    "/bin/bash",
    "/usr/bin/bash",
    "/usr/bin/env",
    "/usr/bin/clear",
    "/usr/bin/sleep",
    "/usr/bin/exo-open",
    "/usr/bin/xfce4-terminal",
    "/usr/bin/dbus-launch",
    "/usr/bin/dbus-daemon",
    "/usr/bin/cargo",
    "/usr/local/bin/cargo",
    "/usr/local/cargo/bin/cargo",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
    "/sbin/init",
    "/usr/sbin/lightdm",
    "/usr/bin/lightdm",
    "/usr/lib/xorg/Xorg",
    "/usr/bin/Xorg",
    "/usr/sbin/getty",
    "/usr/bin/getty",
    "/sbin/getty",
];

pub const IMMUNE_PATH_PREFIXES: &[&str] = &["/lib/systemd/", "/usr/lib/systemd/"];

pub fn observation_is_immune(observation: &ObservationRecord) -> bool {
    if observation
        .executable_path
        .as_deref()
        .is_some_and(path_is_immune)
    {
        return true;
    }

    observation
        .command_line
        .first()
        .is_some_and(|command| command_identifier_is_immune(command))
}

pub fn proposed_action_is_immune(action: Option<&ProposedAction>) -> bool {
    match action {
        Some(ProposedAction::ShellCommand { command }) => command_identifier_is_immune(command),
        _ => false,
    }
}

pub fn command_identifier_is_immune(identifier: &str) -> bool {
    let token = identifier
        .split_whitespace()
        .next()
        .unwrap_or(identifier)
        .trim();
    if token.is_empty() {
        return false;
    }
    path_is_immune(token) || process_name_is_immune(basename(token))
}

pub fn path_is_immune(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }

    IMMUNE_EXACT_PATHS.iter().any(|allowed| trimmed == *allowed)
        || IMMUNE_PATH_PREFIXES
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        || process_name_is_immune(basename(trimmed))
}

pub fn process_name_is_immune(name: &str) -> bool {
    IMMUNE_PROCESS_NAMES.iter().any(|allowed| name == *allowed)
}

pub fn immunity_reason_for_observation(
    observation: &ObservationRecord,
    proposed_action: Option<&ProposedAction>,
) -> Option<&'static str> {
    if observation_is_immune(observation) {
        return Some("system_process_immunity");
    }
    if proposed_action_is_immune(proposed_action) {
        return Some("system_command_immunity");
    }
    None
}

pub fn mcp_caller_is_immune(method: &str, params: &serde_json::Value) -> bool {
    if command_identifier_is_immune(method) {
        return true;
    }

    let Some(obj) = params.as_object() else {
        return false;
    };

    [
        "comm",
        "process",
        "process_name",
        "executable",
        "exe",
        "command",
        "caller",
        "caller_path",
    ]
    .iter()
    .any(|key| {
        obj.get(*key)
            .and_then(|value| value.as_str())
            .is_some_and(command_identifier_is_immune)
    })
}

pub fn immune_exec_path_candidates() -> Vec<String> {
    let mut candidates = HashSet::new();
    for path in IMMUNE_EXACT_PATHS {
        insert_immune_path_candidate(&mut candidates, path);
    }

    collect_path_candidates(&mut candidates);
    collect_systemd_prefix_candidates(&mut candidates);

    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn insert_immune_path_candidate(candidates: &mut HashSet<String>, path: &str) {
    candidates.insert(path.to_string());

    let Ok(canonical) = std::fs::canonicalize(path) else {
        return;
    };
    if let Some(canonical) = canonical.to_str() {
        candidates.insert(canonical.to_string());
    }
}

fn collect_path_candidates(candidates: &mut HashSet<String>) {
    let Some(path_var) = std::env::var_os("PATH") else {
        return;
    };

    for dir in std::env::split_paths(&path_var) {
        for process_name in IMMUNE_PROCESS_NAMES {
            let candidate = dir.join(process_name);
            if candidate.exists() {
                if let Some(candidate) = candidate.to_str() {
                    insert_immune_path_candidate(candidates, candidate);
                }
            }
        }
    }
}

fn collect_systemd_prefix_candidates(candidates: &mut HashSet<String>) {
    for prefix in IMMUNE_PATH_PREFIXES {
        let dir = prefix.trim_end_matches('/');
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };

        for entry in entries.flatten().take(256) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(path) = path.to_str() {
                insert_immune_path_candidate(candidates, path);
            }
        }
    }
}

fn basename(path_or_name: &str) -> &str {
    Path::new(path_or_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path_or_name)
}

#[cfg(test)]
mod system_immunity_tests {
    use super::{immune_exec_path_candidates, path_is_immune, process_name_is_immune};
    use std::path::Path;

    #[test]
    fn system_immunity_process_names_include_posix_shells() {
        assert!(process_name_is_immune("sh"));
        assert!(process_name_is_immune("dash"));
        assert!(process_name_is_immune("bash"));
    }

    #[test]
    fn system_immunity_paths_include_posix_shells() {
        assert!(path_is_immune("/bin/sh"));
        assert!(path_is_immune("/usr/bin/sh"));
        assert!(path_is_immune("/bin/dash"));
        assert!(path_is_immune("/usr/bin/dash"));
        assert!(path_is_immune("/bin/bash"));
        assert!(path_is_immune("/usr/bin/bash"));
        assert!(path_is_immune("/usr/bin/env"));
        assert!(path_is_immune("/usr/bin/exo-open"));
        assert!(path_is_immune("/usr/bin/xfce4-terminal"));
        assert!(path_is_immune("/usr/bin/dbus-launch"));
        assert!(path_is_immune("/usr/bin/dbus-daemon"));
    }

    #[test]
    fn system_immunity_exec_candidates_include_shell_symlinks_and_targets() {
        let candidates = immune_exec_path_candidates();

        if Path::new("/bin/sh").exists() {
            assert!(
                candidates.iter().any(|path| path == "/bin/sh"),
                "immune_exec_path_candidates should preserve /bin/sh"
            );

            if let Ok(canonical) = std::fs::canonicalize("/bin/sh") {
                let canonical = canonical.to_string_lossy().into_owned();
                assert!(
                    candidates.iter().any(|path| path == &canonical),
                    "immune_exec_path_candidates should include canonical /bin/sh target {canonical}"
                );

                if canonical == "/usr/bin/dash" {
                    assert!(
                        candidates.iter().any(|path| path == "/usr/bin/dash"),
                        "immune_exec_path_candidates should include /usr/bin/dash when /bin/sh resolves to it"
                    );
                }
            }
        }

        if Path::new("/usr/bin/sh").exists() {
            assert!(
                candidates.iter().any(|path| path == "/usr/bin/sh"),
                "immune_exec_path_candidates should preserve /usr/bin/sh"
            );
        }
    }
}
