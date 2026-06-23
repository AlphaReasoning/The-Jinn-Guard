// ts_cli/src/ebpf_monitor.rs — eBPF/LSM backend types and loader.
//
// The `LsmRequest`, `LsmRequestType`, `Verdict`, and `VerdictPayload` types are
// always compiled (they're used in the feature-gated verdict loop in main.rs).
//
// The `aya_backend` module is only compiled with `--features kernel_telemetry`.

// ---------------------------------------------------------------------------
// Shared event types (always compiled)
// ---------------------------------------------------------------------------

const LSM_PATH_CACHE_TTL_MS: u64 = 30_000;
const LSM_PATH_CACHE_MAX_ENTRIES: usize = 4096;

/// The type of enforcement request from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmRequestType {
    Connect = 0,
    SendMsg = 1,
    Execve = 2,
    InodeCreate = 3,
    InodeUnlink = 4,
}

/// A request from an LSM hook, asking user-space for a policy decision.
#[derive(Debug, Clone)]
pub struct LsmRequest {
    pub cookie: u64,
    pub pid: u32,
    pub req_type: LsmRequestType,
    pub source_program: u32,
    pub family: u16,
    /// Best-effort controlling TTY marker from `/proc/<pid>/stat`.
    pub tty: Option<String>,
    /// True when the request appears to originate from an interactive user process.
    pub is_interactive: bool,
    /// Best-effort executable path for the process that triggered the LSM event.
    pub process_path: Option<String>,
    /// Raw resource name as reported by the kernel (filename only for inode ops).
    pub resource: String,
    /// Best-effort full path resolved from process context + resource.
    /// Populated before policy evaluation.
    pub resolved_path: Option<String>,
    pub payload_preview: Vec<u8>,
}

impl LsmRequest {
    /// Attempt to resolve the full path for inode operations.
    /// Falls back to the raw resource if /proc resolution fails.
    pub fn resolve_path(&mut self) {
        if matches!(
            self.req_type,
            LsmRequestType::InodeCreate | LsmRequestType::InodeUnlink
        ) {
            self.resolved_path = Some(normalize_lsm_resource_path(self.pid, &self.resource));
        }
        // For non-inode ops, resolved_path stays None and callers use resource.
    }

    /// Populate origin metadata without making policy decisions depend on /proc
    /// availability. Missing process data leaves the request non-interactive.
    pub fn populate_origin(&mut self) {
        self.tty = process_tty(self.pid);
        self.is_interactive = self.tty.is_some();
        self.process_path = process_exe_path(self.pid);
    }

    /// Return the effective path for policy evaluation:
    /// resolved_path if available, otherwise resource.
    pub fn effective_path(&self) -> &str {
        self.resolved_path.as_deref().unwrap_or(&self.resource)
    }
}

pub fn process_tty(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_comm, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();

    // Fields after comm: state, ppid, pgrp, session, tty_nr, ...
    let _state = fields.next()?;
    let _ppid = fields.next()?;
    let _pgrp = fields.next()?;
    let _session = fields.next()?;
    let tty_nr = fields.next()?.parse::<i64>().ok()?;

    if tty_nr == 0 {
        None
    } else {
        Some(format!("tty:{tty_nr}"))
    }
}

pub fn process_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

#[derive(Debug, Clone)]
pub struct CachedPath {
    pub absolute_path: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Default)]
pub struct LsmPathResolutionCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, CachedPath>>,
}

impl LsmPathResolutionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve_request(&self, request: &mut LsmRequest) {
        match request.req_type {
            LsmRequestType::InodeCreate => {
                let normalized = normalize_lsm_resource_path(request.pid, &request.resource);
                request.resolved_path = Some(normalized.clone());
                self.cache_if_scoped(&request.resource, &normalized);
            }
            LsmRequestType::InodeUnlink => {
                if !request.resource.starts_with('/') {
                    if let Some(cached) = self.resolve(&request.resource) {
                        request.resolved_path = Some(cached);
                        return;
                    }
                }
                request.resolved_path =
                    Some(normalize_lsm_resource_path(request.pid, &request.resource));
            }
            _ => {}
        }
    }

    pub fn cache_if_scoped(&self, raw_path: &str, absolute_path: &str) {
        if !path_is_scoped_enforcement_zone(absolute_path) {
            return;
        }

        let key = path_leaf(raw_path);
        if key.is_empty() {
            return;
        }

        let now = current_time_ms();
        let mut entries = self.entries.lock().unwrap_or_else(|err| err.into_inner());
        cleanup_expired_entries(&mut entries, now);
        if entries.len() >= LSM_PATH_CACHE_MAX_ENTRIES {
            entries.clear();
        }
        entries.insert(
            key.to_string(),
            CachedPath {
                absolute_path: absolute_path.to_string(),
                timestamp_ms: now,
            },
        );
    }

    pub fn resolve(&self, raw_path: &str) -> Option<String> {
        let key = path_leaf(raw_path);
        if key.is_empty() {
            return None;
        }

        let now = current_time_ms();
        let mut entries = self.entries.lock().unwrap_or_else(|err| err.into_inner());
        cleanup_expired_entries(&mut entries, now);

        entries.get(key).map(|entry| entry.absolute_path.clone())
    }

    #[cfg(test)]
    pub fn insert_for_test(&self, raw_path: &str, absolute_path: &str, timestamp_ms: u64) {
        let key = path_leaf(raw_path);
        if key.is_empty() {
            return;
        }

        let mut entries = self.entries.lock().unwrap_or_else(|err| err.into_inner());
        entries.insert(
            key.to_string(),
            CachedPath {
                absolute_path: absolute_path.to_string(),
                timestamp_ms,
            },
        );
    }
}

/// Normalize an LSM resource into a best-effort absolute path without panics.
///
/// Inode hooks currently report the dentry basename. Userspace can often recover
/// the operator-visible target from `/proc/<pid>/cmdline`; this is more accurate
/// than blindly joining the basename to cwd for absolute-path invocations such as
/// `touch /tmp/jinnguard-test/file`. If the process has already exited, fall
/// back to known test-zone existence checks and then cwd joining.
pub fn normalize_lsm_resource_path(pid: u32, raw_path: &str) -> String {
    if raw_path.is_empty() {
        return String::new();
    }
    if raw_path.starts_with('/') {
        return raw_path.to_string();
    }

    if let Some(path) = path_from_cmdline(pid, raw_path) {
        return path;
    }
    if let Some(path) = existing_test_zone_path(raw_path) {
        return path;
    }
    if let Some(path) = path_from_cwd(pid, raw_path) {
        return path;
    }

    raw_path.to_string()
}

fn path_from_cmdline(pid: u32, raw_path: &str) -> Option<String> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let raw_leaf = path_leaf(raw_path);

    for arg in cmdline
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
    {
        let Ok(arg) = std::str::from_utf8(arg) else {
            continue;
        };
        if arg.is_empty() {
            continue;
        }
        if arg.starts_with('/') && path_leaf(arg) == raw_leaf {
            return Some(canonical_or_original(arg));
        }
        if path_leaf(arg) == raw_leaf {
            if let Some(path) = path_from_cwd(pid, arg) {
                return Some(path);
            }
        }
    }

    None
}

fn existing_test_zone_path(raw_path: &str) -> Option<String> {
    let leaf = path_leaf(raw_path);
    if leaf.is_empty() {
        return None;
    }

    for base in ["/tmp/jinnguard-test", "/var/tmp/jinnguard-test"] {
        let candidate = std::path::Path::new(base).join(leaf);
        if candidate.exists() {
            return Some(canonical_or_original_path(&candidate));
        }
    }

    let Ok(home_entries) = std::fs::read_dir("/home") else {
        return None;
    };
    for entry in home_entries.flatten().take(256) {
        let candidate = entry.path().join("jinnguard-test").join(leaf);
        if candidate.exists() {
            return Some(canonical_or_original_path(&candidate));
        }
    }

    None
}

fn path_from_cwd(pid: u32, raw_path: &str) -> Option<String> {
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
    let candidate = cwd.join(raw_path);
    Some(canonical_or_original_path(&candidate))
}

fn canonical_or_original(path: &str) -> String {
    let path = std::path::Path::new(path);
    canonical_or_original_path(path)
}

fn canonical_or_original_path(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn path_leaf(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

pub fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn cleanup_expired_entries(
    entries: &mut std::collections::HashMap<String, CachedPath>,
    now_ms: u64,
) {
    entries.retain(|_, entry| now_ms.saturating_sub(entry.timestamp_ms) <= LSM_PATH_CACHE_TTL_MS);
}

fn path_is_scoped_enforcement_zone(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }

    path.starts_with("/tmp/jinnguard-test/")
        || path.starts_with("/var/tmp/jinnguard-test/")
        || home_jinnguard_test_path(path)
}

fn home_jinnguard_test_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/home/") else {
        return false;
    };
    let Some((_user, suffix)) = rest.split_once('/') else {
        return false;
    };
    suffix.starts_with("jinnguard-test/")
}

/// A policy verdict sent from user-space back to the kernel.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Verdict {
    Unknown = 0,
    Allow = 1,
    Deny = 2,
}

/// The payload written to the 'verdicts' BPF hash map.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VerdictPayload {
    pub cookie: u64,
    pub verdict: u32,
}

// ---------------------------------------------------------------------------
// aya-rs LSM hook loader and enforcer (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kernel_telemetry")]
pub mod aya_backend {
    use super::{LsmRequest, LsmRequestType, Verdict, VerdictPayload};
    use crate::{system_immunity, PolicyConfig};
    use anyhow::{anyhow, Result};
    use aya::{
        maps::{ring_buf::RingBuf, Array as AyaArray, HashMap as AyaHashMap, MapData},
        programs::Lsm,
        Btf, Ebpf,
    };
    use std::collections::HashMap as StdHashMap;
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::MetadataExt;

    unsafe impl aya::Pod for VerdictPayload {}

    const JG_MAX_RESOURCE_LEN: usize = 128;
    const JG_CONTROL_KEY: u32 = 0;
    const JG_CONTROL_AUDIT_ONLY: u32 = 1;
    // Bit 1: deny non-allowlisted governed-scope network egress (#54).
    const JG_CONTROL_CONNECT_DEFAULT_DENY: u32 = 2;
    // Bit 2: deny non-allowlisted governed-scope AF_UNIX egress (#56).
    const JG_CONTROL_UNIX_DEFAULT_DENY: u32 = 4;
    // Key 0 of the per-object `governed_scope` array. Value 0 = govern every
    // task (historical/deployed default); a non-zero cgroup-v2 id confines
    // enforcement to that one cgroup so the operator's desktop is never denied.
    const JG_SCOPE_KEY: u32 = 0;
    const JG_SCOPE_GLOBAL: u64 = 0;
    const JG_SRC_INODE_CREATE: u32 = 1;
    const JG_SRC_INODE_UNLINK: u32 = 2;
    const JG_SRC_BPRM_CHECK_SECURITY: u32 = 3;
    const JG_SRC_SOCKET_CONNECT: u32 = 4;
    const JG_SRC_SOCKET_SENDMSG: u32 = 5;
    // Capability hook (JG #53). Emits no requests; the value only labels the
    // loaded object and is never used for request routing.
    const JG_SRC_CAPABLE: u32 = 7;
    // Mount-nesting primitive hooks (JG #50). Pure kernel-floor deny-in-scope
    // hooks; emit no requests, the value only labels the loaded object.
    const JG_SRC_SB_MOUNT: u32 = 8;
    const JG_SRC_SB_PIVOTROOT: u32 = 9;
    const JG_SRC_MOVE_MOUNT: u32 = 10;
    // VM-launch device hook (JG #51): denies /dev/kvm open in governed scope.
    // Pure kernel-floor deny; emits no requests, value only labels the object.
    const JG_SRC_FILE_OPEN: u32 = 11;
    /// Policy path key used by BPF maps.
    /// Must match `struct jg_path_key` in `bpf/lsm/jg_common.h`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PathKey {
        path: [u8; JG_MAX_RESOURCE_LEN],
    }

    unsafe impl aya::Pod for PathKey {}

    /// Collision-free directory identity used by the `denied_dir_inodes` map.
    /// Must match `struct jg_inode_key` in `bpf/lsm/jg_common.h`: (dev, ino),
    /// both `u64` so there is no padding hole in the hashed key.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InodeKey {
        dev: u64,
        ino: u64,
    }

    unsafe impl aya::Pod for InodeKey {}

    /// Precise per-file denial key for the `denied_files_in_dir` map.
    /// Must match `struct jg_dir_file_key` in `bpf/lsm/jg_common.h`:
    /// (parent dev, parent ino, NUL-padded basename) = (u64, u64, [u8; 128]),
    /// 144 bytes with no padding hole.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DirFileKey {
        dev: u64,
        ino: u64,
        name: [u8; JG_MAX_RESOURCE_LEN],
    }

    unsafe impl aya::Pod for DirFileKey {}

    /// Raw request layout from the eBPF ring buffer.
    /// Must match `jg_request` in `bpf/lsm/jg_common.h`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawLsmRequest {
        pub cookie: u64,
        pub pid: u32,
        pub req_type: u32,
        pub family: u16,
        pub resource_path: [u8; 128],
        pub _pad_after_resource: [u8; 2],
        pub dest: [u8; 108],
        pub payload_preview: [u8; 64],
        pub source_program: u32,
    }

    const _: [(); 328] = [(); std::mem::size_of::<RawLsmRequest>()];
    const _: [(); 0] = [(); std::mem::offset_of!(RawLsmRequest, cookie)];
    const _: [(); 8] = [(); std::mem::offset_of!(RawLsmRequest, pid)];
    const _: [(); 12] = [(); std::mem::offset_of!(RawLsmRequest, req_type)];
    const _: [(); 16] = [(); std::mem::offset_of!(RawLsmRequest, family)];
    const _: [(); 18] = [(); std::mem::offset_of!(RawLsmRequest, resource_path)];
    const _: [(); 146] = [(); std::mem::offset_of!(RawLsmRequest, _pad_after_resource)];
    const _: [(); 148] = [(); std::mem::offset_of!(RawLsmRequest, dest)];
    const _: [(); 256] = [(); std::mem::offset_of!(RawLsmRequest, payload_preview)];
    const _: [(); 320] = [(); std::mem::offset_of!(RawLsmRequest, source_program)];
    const _: [(); 16] = [(); std::mem::size_of::<VerdictPayload>()];

    impl TryFrom<RawLsmRequest> for LsmRequest {
        type Error = anyhow::Error;

        fn try_from(raw: RawLsmRequest) -> Result<Self> {
            let req_type = match raw.req_type {
                0 => LsmRequestType::Connect,
                1 => LsmRequestType::SendMsg,
                2 => LsmRequestType::Execve,
                3 => LsmRequestType::InodeCreate,
                4 => LsmRequestType::InodeUnlink,
                _ => return Err(anyhow!("Invalid LsmRequestType: {}", raw.req_type)),
            };

            let resource = format_resource(&raw, req_type)?;

            let payload_preview = raw
                .payload_preview
                .iter()
                .take_while(|&&b| b != 0)
                .cloned()
                .collect();

            let mut req = LsmRequest {
                cookie: raw.cookie,
                pid: raw.pid,
                req_type,
                source_program: raw.source_program,
                family: raw.family,
                tty: None,
                is_interactive: false,
                process_path: None,
                resource,
                resolved_path: None,
                payload_preview,
            };
            // Attempt full-path resolution for inode operations.
            req.resolve_path();
            req.populate_origin();
            Ok(req)
        }
    }

    fn nul_terminated_string(bytes: &[u8]) -> Result<String> {
        Ok(String::from_utf8(
            bytes.iter().take_while(|&&b| b != 0).cloned().collect(),
        )?)
    }

    fn format_resource(raw: &RawLsmRequest, req_type: LsmRequestType) -> Result<String> {
        if matches!(
            req_type,
            LsmRequestType::Execve | LsmRequestType::InodeCreate | LsmRequestType::InodeUnlink
        ) {
            return nul_terminated_string(&raw.resource_path);
        }

        match raw.family as i32 {
            libc::AF_INET => {
                let ip =
                    std::net::Ipv4Addr::new(raw.dest[0], raw.dest[1], raw.dest[2], raw.dest[3]);
                let port = u16::from_be_bytes([raw.dest[4], raw.dest[5]]);
                Ok(format!("{ip}:{port}"))
            }
            libc::AF_INET6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw.dest[..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([raw.dest[16], raw.dest[17]]);
                Ok(format!("[{ip}]:{port}"))
            }
            libc::AF_UNIX => nul_terminated_string(&raw.dest),
            other => Ok(format!("family:{other}")),
        }
    }

    struct LoadedLsmObject {
        bpf: Ebpf,
        object_path: &'static str,
        // Retained so the program can be attached later, after policy maps are
        // populated (see AyaLsmMonitor::attach_all / the load-window fail-open fix).
        prog_name: &'static str,
        hook_name: &'static str,
        source_program: u32,
        verdicts: AyaHashMap<MapData, u64, VerdictPayload>,
        runtime_controls: Option<AyaArray<MapData, u32>>,
        // Set once before attach (see load_lsm_object); retained only to keep the
        // map handle owned for the object's lifetime.
        #[allow(dead_code)]
        governed_scope: Option<AyaArray<MapData, u64>>,
        ipv4_denylist: Option<AyaHashMap<MapData, u32, u8>>,
        // #54: IPv4 egress allowlist, consulted by socket_connect under default-deny.
        ipv4_allowlist: Option<AyaHashMap<MapData, u32, u8>>,
        // #55: AF_UNIX orchestrator/control-socket denylist for socket_connect.
        unix_denylist: Option<AyaHashMap<MapData, PathKey, u8>>,
        // #56: AF_UNIX egress allowlist, consulted under UNIX default-deny.
        unix_allowlist: Option<AyaHashMap<MapData, PathKey, u8>>,
        allowed_exec_paths: Option<AyaHashMap<MapData, PathKey, u8>>,
        denied_basenames: Option<AyaHashMap<MapData, PathKey, u8>>,
        denied_dir_inodes: Option<AyaHashMap<MapData, InodeKey, u8>>,
        denied_files_in_dir: Option<AyaHashMap<MapData, DirFileKey, u8>>,
    }

    /// The main user-space monitor for loading LSM hooks and handling requests.
    pub struct AyaLsmMonitor {
        objects: Vec<LoadedLsmObject>,
        requests: RingBuf<MapData>,
        program_routes: StdHashMap<u32, usize>,
        pending_routes: StdHashMap<u64, usize>,
    }

    impl AyaLsmMonitor {
        pub fn load(safe_mode: bool) -> Result<Self> {
            // A previous daemon instance may have left the LIBBPF_PIN_BY_NAME
            // 'requests' ring buffer pinned in bpffs. Reusing that stale buffer
            // on restart leaves us attached to a buffer that delivers no events
            // (synchronous enforcement still works, but telemetry goes silent).
            // Clear it first so we always start with a fresh ring buffer.
            clear_stale_request_pin();

            let btf = Btf::from_sys_fs()
                .map_err(|e| anyhow!("aya: failed to load kernel BTF from sysfs: {}", e))?;

            // Resolve the enforcement scope ONCE, before any program attaches, so
            // there is never a window in which hooks enforce host-wide. Default
            // (env unset) is 0 = global, preserving the deployed behavior; setting
            // JINNGUARD_GOVERN_CGROUP=<cgroup-v2 dir> confines enforcement to that
            // cgroup. If a scope is requested but cannot be resolved we refuse to
            // start rather than silently fall back to host-wide enforcement.
            let governed_cgroup_id = resolve_governed_scope()?;

            let lsm_objects = [
                (
                    JG_SRC_SOCKET_CONNECT,
                    "/usr/lib/jinnguard/lsm/jg_socket_connect.o",
                    "jg_socket_connect",
                    "socket_connect",
                ),
                (
                    JG_SRC_SOCKET_SENDMSG,
                    "/usr/lib/jinnguard/lsm/jg_socket_sendmsg.o",
                    "jg_socket_sendmsg",
                    "socket_sendmsg",
                ),
                (
                    JG_SRC_BPRM_CHECK_SECURITY,
                    "/usr/lib/jinnguard/lsm/jg_bprm_check_security.o",
                    "jg_bprm_check_security",
                    "bprm_check_security",
                ),
                (
                    JG_SRC_INODE_CREATE,
                    "/usr/lib/jinnguard/lsm/jg_inode_create.o",
                    "jg_inode_create",
                    "inode_create",
                ),
                (
                    JG_SRC_INODE_UNLINK,
                    "/usr/lib/jinnguard/lsm/jg_inode_unlink.o",
                    "jg_inode_unlink",
                    "inode_unlink",
                ),
                // Capability hook (JG #53): denies escalation caps wielded inside
                // a nested user namespace by governed tasks, restricting
                // unprivileged-userns nesting. Emits no requests.
                (
                    JG_SRC_CAPABLE,
                    "/usr/lib/jinnguard/lsm/jg_capable.o",
                    "jg_capable",
                    "capable",
                ),
                // Mount-nesting primitive hooks (JG #50): deny mount / pivot_root
                // / move_mount for governed tasks so a governed agent cannot
                // assemble a nested container/sandbox root outside host LSM scope.
                // Pure kernel-floor deny-in-scope; emit no requests.
                (
                    JG_SRC_SB_MOUNT,
                    "/usr/lib/jinnguard/lsm/jg_sb_mount.o",
                    "jg_sb_mount",
                    "sb_mount",
                ),
                (
                    JG_SRC_SB_PIVOTROOT,
                    "/usr/lib/jinnguard/lsm/jg_sb_pivotroot.o",
                    "jg_sb_pivotroot",
                    "sb_pivotroot",
                ),
                (
                    JG_SRC_MOVE_MOUNT,
                    "/usr/lib/jinnguard/lsm/jg_move_mount.o",
                    "jg_move_mount",
                    "move_mount",
                ),
                // VM-launch device hook (JG #51): deny /dev/kvm open for governed
                // tasks so an agent cannot launch a KVM-accelerated VM/microVM and
                // escape the host LSM scope inside a guest kernel. Pure kernel-floor
                // deny-in-scope; matches the device by fixed (major 10, minor 232).
                (
                    JG_SRC_FILE_OPEN,
                    "/usr/lib/jinnguard/lsm/jg_file_open.o",
                    "jg_file_open",
                    "file_open",
                ),
            ];

            let mut objects = Vec::new();
            let mut requests = None;
            for (index, (source_program, object_path, prog_name, hook_name)) in
                lsm_objects.into_iter().enumerate()
            {
                let (object, object_requests) = load_lsm_object(
                    source_program,
                    object_path,
                    prog_name,
                    hook_name,
                    &btf,
                    safe_mode,
                    governed_cgroup_id,
                    index == 0,
                )?;
                if object_requests.is_some() && requests.is_some() {
                    return Err(anyhow!(
                        "internal loader error: multiple requests ring buffer readers created"
                    ));
                }
                requests = requests.or(object_requests);
                objects.push(object);
            }
            let requests = requests
                .ok_or_else(|| anyhow!("eBPF map 'requests' not found in any loaded LSM object"))?;
            let program_routes = objects
                .iter()
                .enumerate()
                .map(|(index, object)| (object.source_program, index))
                .collect();

            if safe_mode {
                eprintln!("[safe-mode] LSM audit-only mode active; deny decisions disabled");
            }

            Ok(Self {
                objects,
                requests,
                program_routes,
                pending_routes: StdHashMap::new(),
            })
        }

        /// Attach every loaded LSM program to its hook.
        ///
        /// MUST be called only AFTER [`configure_policy`](Self::configure_policy)
        /// has populated the in-kernel deny maps. `load` deliberately loads the
        /// programs without attaching them: attaching a hook before its policy
        /// map is populated leaves a window in which the hook consults an empty
        /// map and ALLOWS the operation (fail OPEN). Populate-then-attach removes
        /// that window entirely. See THREAT_MODEL.md (load-window fail-open).
        pub(crate) fn attach_all(&mut self) -> Result<()> {
            for object in &mut self.objects {
                let prog: &mut Lsm = object
                    .bpf
                    .program_mut(object.prog_name)
                    .ok_or_else(|| {
                        anyhow!(
                            "eBPF program '{}' not found in {}",
                            object.prog_name,
                            object.object_path
                        )
                    })?
                    .try_into()?;
                prog.attach()?;
                println!(
                    "[eBPF LSM] Attached '{}' from '{}' to '{}' hook.",
                    object.prog_name, object.object_path, object.hook_name
                );
            }
            Ok(())
        }

        /// Populate in-kernel policy maps before hooks are used for enforcement.
        ///
        /// LSM hooks cannot sleep while waiting for a user-space decision, so the
        /// synchronous allow/deny path must consult maps that are already loaded.
        pub(crate) fn configure_policy(
            &mut self,
            policy: &PolicyConfig,
            safe_mode: bool,
            daemon_socket_path: &str,
        ) -> Result<()> {
            self.configure_runtime_controls(
                safe_mode,
                policy.network_policy.default_deny,
                policy.network_policy.unix_default_deny,
            )?;

            for object in &mut self.objects {
                if let Some(map) = object.ipv4_denylist.as_mut() {
                    configure_ipv4_denylist(map, policy, object.object_path)?;
                }
                if let Some(map) = object.ipv4_allowlist.as_mut() {
                    configure_ipv4_allowlist(map, policy, object.object_path)?;
                }
                if let Some(map) = object.unix_denylist.as_mut() {
                    configure_unix_denylist(map, policy, object.object_path)?;
                }
                if let Some(map) = object.unix_allowlist.as_mut() {
                    configure_unix_allowlist(map, policy, daemon_socket_path, object.object_path)?;
                }
                if let Some(map) = object.allowed_exec_paths.as_mut() {
                    configure_allowed_exec_paths(map, policy, object.object_path)?;
                }
                let denied_paths = denied_paths_for_object(policy, object.object_path);
                if !denied_paths.is_empty() {
                    if let Some(map) = object.denied_dir_inodes.as_mut() {
                        configure_denied_dir_inodes(
                            map,
                            denied_paths.iter().copied(),
                            object.object_path,
                        )?;
                    }
                    if let Some(map) = object.denied_files_in_dir.as_mut() {
                        configure_denied_files_in_dir(
                            map,
                            denied_paths.iter().copied(),
                            object.object_path,
                        )?;
                    }
                    if let Some(map) = object.denied_basenames.as_mut() {
                        configure_denied_basenames(
                            map,
                            denied_paths.iter().copied(),
                            object.object_path,
                        )?;
                    }
                }
            }
            Ok(())
        }

        fn configure_runtime_controls(
            &mut self,
            safe_mode: bool,
            default_deny: bool,
            unix_default_deny: bool,
        ) -> Result<()> {
            let mut control_value = 0u32;
            if safe_mode {
                control_value |= JG_CONTROL_AUDIT_ONLY;
            }
            if default_deny {
                control_value |= JG_CONTROL_CONNECT_DEFAULT_DENY;
            }
            if unix_default_deny {
                control_value |= JG_CONTROL_UNIX_DEFAULT_DENY;
            }
            for object in &mut self.objects {
                let Some(map) = object.runtime_controls.as_mut() else {
                    if safe_mode {
                        return Err(anyhow!(
                            "safe mode requested, but runtime_controls map is missing in {}",
                            object.object_path
                        ));
                    }
                    continue;
                };

                map.set(JG_CONTROL_KEY, control_value, 0).map_err(|e| {
                    anyhow!(
                        "Failed to set runtime_controls in {} to {}: {}",
                        object.object_path,
                        control_value,
                        e
                    )
                })?;
            }
            Ok(())
        }

        /// Submit a verdict for a given request cookie back to the kernel.
        pub fn send_verdict(&mut self, cookie: u64, verdict: Verdict) -> Result<()> {
            let object_index = self.pending_routes.remove(&cookie).ok_or_else(|| {
                anyhow!(
                    "No loaded LSM object route recorded for request cookie {}",
                    cookie
                )
            })?;
            let payload = VerdictPayload {
                cookie,
                verdict: verdict as u32,
            };
            self.objects
                .get_mut(object_index)
                .ok_or_else(|| anyhow!("Invalid LSM object route index {}", object_index))?
                .verdicts
                .insert(cookie, payload, 0)
                .map_err(|e| anyhow!("Failed to send verdict to kernel map: {}", e))?;
            Ok(())
        }

        /// Poll and parse requests from the ring buffer.
        pub fn poll_requests(&mut self) -> Result<Vec<LsmRequest>> {
            let mut parsed_requests = Vec::new();
            while let Some(bytes) = self.requests.next() {
                if bytes.len() >= std::mem::size_of::<RawLsmRequest>() {
                    let raw_req: RawLsmRequest =
                        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawLsmRequest) };
                    match LsmRequest::try_from(raw_req) {
                        Ok(req) => {
                            let route = self
                                .program_routes
                                .get(&req.source_program)
                                .copied()
                                .or_else(|| {
                                    source_program_for_request_type(req.req_type).and_then(
                                        |source_program| {
                                            self.program_routes.get(&source_program).copied()
                                        },
                                    )
                                });
                            if let Some(route) = route {
                                self.pending_routes.insert(req.cookie, route);
                                parsed_requests.push(req);
                            } else {
                                eprintln!(
                                    "[eBPF LSM] no route for source_program={} req_type={:?}; dropping verdict feedback for cookie={}",
                                    req.source_program, req.req_type, req.cookie
                                );
                            }
                        }
                        Err(e) => eprintln!("[eBPF LSM] Error parsing raw request: {}", e),
                    }
                }
            }
            Ok(parsed_requests)
        }
    }

    fn source_program_for_request_type(req_type: LsmRequestType) -> Option<u32> {
        Some(match req_type {
            LsmRequestType::Connect => JG_SRC_SOCKET_CONNECT,
            LsmRequestType::SendMsg => JG_SRC_SOCKET_SENDMSG,
            LsmRequestType::Execve => JG_SRC_BPRM_CHECK_SECURITY,
            LsmRequestType::InodeCreate => JG_SRC_INODE_CREATE,
            LsmRequestType::InodeUnlink => JG_SRC_INODE_UNLINK,
        })
    }

    /// Remove a stale pinned `requests` ring buffer left by a previous daemon
    /// instance. The map is pinned LIBBPF_PIN_BY_NAME (see bpf/common/maps.h) so
    /// it outlives the process; aya reuses the existing pin on the next load,
    /// which re-attaches the new daemon to an old, drained ring buffer. Removing
    /// the pin forces aya to create and pin a fresh buffer. The bpffs default
    /// mount is /sys/fs/bpf; the map name is the pin file name.
    fn clear_stale_request_pin() {
        for path in ["/sys/fs/bpf/requests", "/sys/fs/bpf/jinnguard/requests"] {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    eprintln!("[eBPF LSM] cleared stale pinned ring buffer at {path}")
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!(
                    "[eBPF LSM] warning: could not remove stale ring buffer pin {path}: {e}"
                ),
            }
        }
    }

    // Loads one LSM object (program + maps + scope) but does NOT attach it;
    // attaching is deferred to AyaLsmMonitor::attach_all after policy load.
    #[allow(clippy::too_many_arguments)]
    fn load_lsm_object(
        source_program: u32,
        object_path: &'static str,
        prog_name: &'static str,
        hook_name: &'static str,
        btf: &Btf,
        safe_mode: bool,
        governed_cgroup_id: u64,
        take_requests: bool,
    ) -> Result<(LoadedLsmObject, Option<RingBuf<MapData>>)> {
        let data = std::fs::read(object_path)
            .map_err(|e| anyhow!("Failed to read eBPF LSM object {}: {}", object_path, e))?;

        let mut bpf = Ebpf::load(&data)
            .map_err(|e| anyhow!("aya: failed to load eBPF LSM object {}: {}", object_path, e))?;

        {
            let prog: &mut Lsm = bpf
                .program_mut(prog_name)
                .ok_or_else(|| {
                    anyhow!("eBPF program '{}' not found in {}", prog_name, object_path)
                })?
                .try_into()?;
            prog.load(hook_name, btf)?;
        }

        let mut runtime_controls = optional_array_map(&mut bpf, "runtime_controls", object_path)?;
        if safe_mode {
            runtime_controls
                .as_mut()
                .ok_or_else(|| {
                    anyhow!(
                        "safe mode requested, but runtime_controls map is missing in {}",
                        object_path
                    )
                })?
                .set(JG_CONTROL_KEY, JG_CONTROL_AUDIT_ONLY, 0)
                .map_err(|e| {
                    anyhow!(
                        "Failed to enable safe mode in runtime_controls for {}: {}",
                        object_path,
                        e
                    )
                })?;
        }

        // Confine enforcement to the requested cgroup BEFORE attaching, so the
        // hook never runs host-wide. A value of 0 (default) means global. If a
        // non-global scope is requested but the map is absent (older object),
        // refuse to attach rather than enforce host-wide unexpectedly.
        let mut governed_scope = optional_array_map(&mut bpf, "governed_scope", object_path)?;
        match governed_scope.as_mut() {
            Some(map) => {
                map.set(JG_SCOPE_KEY, governed_cgroup_id, 0).map_err(|e| {
                    anyhow!(
                        "Failed to set governed_scope in {} to {}: {}",
                        object_path,
                        governed_cgroup_id,
                        e
                    )
                })?;
            }
            None if governed_cgroup_id != JG_SCOPE_GLOBAL => {
                return Err(anyhow!(
                    "cgroup-scoped enforcement requested, but governed_scope map is missing in {} (rebuild the LSM objects)",
                    object_path
                ));
            }
            None => {}
        }

        // NOTE: the program is intentionally NOT attached here. Attaching is
        // deferred to AyaLsmMonitor::attach_all(), which the caller invokes only
        // AFTER configure_policy() has populated the in-kernel deny maps. A hook
        // attached before its policy map is populated would consult an empty map
        // and ALLOW the operation (fail OPEN) for the duration of that window.
        // See THREAT_MODEL.md (load-window fail-open).

        let requests = if take_requests {
            Some(RingBuf::try_from(bpf.take_map("requests").ok_or_else(
                || anyhow!("eBPF map 'requests' not found in {}", object_path),
            )?)?)
        } else {
            None
        };

        let verdicts: AyaHashMap<_, u64, VerdictPayload> = AyaHashMap::try_from(
            bpf.take_map("verdicts")
                .ok_or_else(|| anyhow!("eBPF map 'verdicts' not found in {}", object_path))?,
        )?;

        let ipv4_denylist = optional_hash_map(&mut bpf, "ipv4_denylist", object_path)?;
        let ipv4_allowlist = optional_hash_map(&mut bpf, "ipv4_allowlist", object_path)?;
        let unix_denylist = optional_hash_map(&mut bpf, "unix_denylist", object_path)?;
        let unix_allowlist = optional_hash_map(&mut bpf, "unix_allowlist", object_path)?;
        let allowed_exec_paths = optional_hash_map(&mut bpf, "allowed_exec_paths", object_path)?;
        let denied_basenames = optional_hash_map(&mut bpf, "denied_basenames", object_path)?;
        let denied_dir_inodes = optional_hash_map(&mut bpf, "denied_dir_inodes", object_path)?;
        let denied_files_in_dir = optional_hash_map(&mut bpf, "denied_files_in_dir", object_path)?;

        Ok((
            LoadedLsmObject {
                bpf,
                object_path,
                prog_name,
                hook_name,
                source_program,
                verdicts,
                runtime_controls,
                governed_scope,
                ipv4_denylist,
                ipv4_allowlist,
                unix_denylist,
                unix_allowlist,
                allowed_exec_paths,
                denied_basenames,
                denied_dir_inodes,
                denied_files_in_dir,
            },
            requests,
        ))
    }

    /// Resolve the configured enforcement scope to a cgroup-v2 id (0 = global).
    ///
    /// `JINNGUARD_GOVERN_CGROUP` may name a cgroup-v2 directory (e.g.
    /// `/sys/fs/cgroup/jinnguard`); only tasks in that cgroup are then governed.
    /// Unset/empty means host-wide enforcement (the deployed default). A set but
    /// unresolvable path is a hard error — we never silently widen the scope.
    fn resolve_governed_scope() -> Result<u64> {
        match std::env::var("JINNGUARD_GOVERN_CGROUP") {
            Ok(path) if !path.is_empty() => {
                let id = resolve_cgroup_id(&path)?;
                eprintln!(
                    "[eBPF LSM] enforcement confined to cgroup {path} (id {id}); all other tasks pass through"
                );
                Ok(id)
            }
            _ => Ok(JG_SCOPE_GLOBAL),
        }
    }

    /// Return the cgroup-v2 id of a cgroup directory, matching the value the
    /// kernel's `bpf_get_current_cgroup_id()` reports for tasks in it. The id is
    /// the 64-bit kernfs node id encoded in the directory's NFS file handle.
    fn resolve_cgroup_id(path: &str) -> Result<u64> {
        #[repr(C)]
        struct FileHandleBuf {
            handle_bytes: libc::c_uint,
            handle_type: libc::c_int,
            f_handle: [u8; 128],
        }

        let c_path = std::ffi::CString::new(path)
            .map_err(|e| anyhow!("invalid cgroup path {}: {}", path, e))?;
        let mut handle = FileHandleBuf {
            handle_bytes: 128,
            handle_type: 0,
            f_handle: [0u8; 128],
        };
        let mut mount_id: libc::c_int = 0;
        let ret = unsafe {
            libc::name_to_handle_at(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                &mut handle as *mut FileHandleBuf as *mut libc::file_handle,
                &mut mount_id,
                0,
            )
        };
        if ret != 0 {
            return Err(anyhow!(
                "could not resolve cgroup id for {} (is it a cgroup-v2 directory?): {}",
                path,
                std::io::Error::last_os_error()
            ));
        }
        if (handle.handle_bytes as usize) < std::mem::size_of::<u64>() {
            return Err(anyhow!(
                "unexpected cgroup file-handle size {} for {}",
                handle.handle_bytes,
                path
            ));
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&handle.f_handle[..8]);
        Ok(u64::from_le_bytes(id_bytes))
    }

    fn optional_array_map<V>(
        bpf: &mut Ebpf,
        map_name: &str,
        object_path: &str,
    ) -> Result<Option<AyaArray<MapData, V>>>
    where
        V: aya::Pod,
    {
        let Some(map) = bpf.take_map(map_name) else {
            return Ok(None);
        };
        AyaArray::try_from(map).map(Some).map_err(|e| {
            anyhow!(
                "Failed to open eBPF array map '{}' in {}: {}",
                map_name,
                object_path,
                e
            )
        })
    }

    fn optional_hash_map<K, V>(
        bpf: &mut Ebpf,
        map_name: &str,
        object_path: &str,
    ) -> Result<Option<AyaHashMap<MapData, K, V>>>
    where
        K: aya::Pod,
        V: aya::Pod,
    {
        let Some(map) = bpf.take_map(map_name) else {
            return Ok(None);
        };
        AyaHashMap::try_from(map).map(Some).map_err(|e| {
            anyhow!(
                "Failed to open eBPF map '{}' in {}: {}",
                map_name,
                object_path,
                e
            )
        })
    }

    fn configure_ipv4_denylist(
        map: &mut AyaHashMap<MapData, u32, u8>,
        policy: &PolicyConfig,
        object_path: &str,
    ) -> Result<()> {
        for entry in &policy.network_policy.denied_ips {
            let Some(key) = ipv4_policy_key(entry) else {
                eprintln!(
                    "[eBPF LSM] skipping unsupported IPv4 denylist entry '{}' for {}",
                    entry, object_path
                );
                continue;
            };
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate ipv4_denylist entry '{}' in {}: {}",
                    entry,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    /// #54: populate the IPv4 egress allowlist from `network_policy.allowed_ips`.
    /// Only consulted in-kernel when default-deny is enabled, so it is harmless
    /// (and cheap) to populate unconditionally.
    fn configure_ipv4_allowlist(
        map: &mut AyaHashMap<MapData, u32, u8>,
        policy: &PolicyConfig,
        object_path: &str,
    ) -> Result<()> {
        for entry in &policy.network_policy.allowed_ips {
            let Some(key) = ipv4_policy_key(entry) else {
                eprintln!(
                    "[eBPF LSM] skipping unsupported IPv4 allowlist entry '{}' for {}",
                    entry, object_path
                );
                continue;
            };
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate ipv4_allowlist entry '{}' in {}: {}",
                    entry,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    /// Built-in orchestrator / init control sockets a governed agent must never
    /// reach directly — connecting to one lets the agent borrow that daemon's
    /// ungoverned root authority (the confused-deputy path, #55). Both the
    /// `/run` and legacy `/var/run` locations are listed because `/var/run` is a
    /// symlink to `/run` on most distros but agents may use either literal path.
    const ORCHESTRATOR_CONTROL_SOCKETS: &[&str] = &[
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
        "/run/crio/crio.sock",
        "/var/run/crio/crio.sock",
        "/run/libvirt/libvirt-sock",
        "/var/run/libvirt/libvirt-sock",
        "/run/libvirt/libvirt-sock-ro",
        "/var/run/libvirt/libvirt-sock-ro",
        "/run/dbus/system_bus_socket",
        "/var/run/dbus/system_bus_socket",
        "/run/systemd/private",
        "/var/run/systemd/private",
    ];

    /// #55: populate the AF_UNIX deputy-socket denylist (built-in orchestrator
    /// sockets). Exact pathname match; abstract-namespace sockets are out of
    /// scope (a documented limitation).
    fn configure_unix_denylist(
        map: &mut AyaHashMap<MapData, PathKey, u8>,
        _policy: &PolicyConfig,
        object_path: &str,
    ) -> Result<()> {
        for path in ORCHESTRATOR_CONTROL_SOCKETS {
            let key = path_key(path);
            if key.path[0] == 0 {
                continue;
            }
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate unix_denylist entry '{}' in {}: {}",
                    path,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    /// #56: populate the AF_UNIX egress allowlist from
    /// `network_policy.allowed_unix_sockets`, plus the Jinn Guard control socket
    /// itself — which is added unconditionally so a governed agent can always
    /// reach its own governor even under UNIX default-deny (anti-lockout).
    fn configure_unix_allowlist(
        map: &mut AyaHashMap<MapData, PathKey, u8>,
        policy: &PolicyConfig,
        daemon_socket_path: &str,
        object_path: &str,
    ) -> Result<()> {
        let entries = std::iter::once(daemon_socket_path).chain(
            policy
                .network_policy
                .allowed_unix_sockets
                .iter()
                .map(String::as_str),
        );
        for path in entries {
            let key = path_key(path);
            if key.path[0] == 0 {
                continue;
            }
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate unix_allowlist entry '{}' in {}: {}",
                    path,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    fn configure_allowed_exec_paths(
        map: &mut AyaHashMap<MapData, PathKey, u8>,
        policy: &PolicyConfig,
        object_path: &str,
    ) -> Result<()> {
        for path in system_immunity::immune_exec_path_candidates() {
            insert_allowed_exec_path(map, &path, object_path)?;
        }

        for path in policy
            .agent_nodes
            .values()
            .flat_map(|node| node.allowed_executables.iter())
        {
            insert_allowed_exec_path(map, path, object_path)?;
        }
        Ok(())
    }

    fn insert_allowed_exec_path(
        map: &mut AyaHashMap<MapData, PathKey, u8>,
        path: &str,
        object_path: &str,
    ) -> Result<()> {
        let key = path_key(path);
        if key.path[0] == 0 {
            return Ok(());
        }
        map.insert(key, 1, 0).map_err(|e| {
            anyhow!(
                "Failed to populate allowed_exec_paths entry '{}' in {}: {}",
                path,
                object_path,
                e
            )
        })?;
        Ok(())
    }

    fn configure_denied_dir_inodes<'a, I>(
        map: &mut AyaHashMap<MapData, InodeKey, u8>,
        paths: I,
        object_path: &str,
    ) -> Result<()>
    where
        I: IntoIterator<Item = &'a String>,
    {
        for path in paths {
            let Some(key) = denied_dir_inode(path)? else {
                continue;
            };
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate denied_dir_inodes entry '{}' dev={} ino={} in {}: {}",
                    path,
                    key.dev,
                    key.ino,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    fn configure_denied_basenames<'a, I>(
        map: &mut AyaHashMap<MapData, PathKey, u8>,
        paths: I,
        object_path: &str,
    ) -> Result<()>
    where
        I: IntoIterator<Item = &'a String>,
    {
        for path in paths {
            if denied_entry_is_existing_dir(path) {
                continue;
            }
            // Entries whose parent directory resolves at load time are matched
            // precisely by `denied_files_in_dir` (dev, ino, basename); only fall
            // back to the basename-anywhere map when that precise key is
            // unavailable, so this map never over-blocks an entry we can pin.
            if denied_file_parent_key(path)?.is_some() {
                continue;
            }
            let key = path_key(filesystem_policy_leaf(path));
            if key.path[0] == 0 {
                continue;
            }
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate denied_basenames entry '{}' in {}: {}",
                    path,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    fn configure_denied_files_in_dir<'a, I>(
        map: &mut AyaHashMap<MapData, DirFileKey, u8>,
        paths: I,
        object_path: &str,
    ) -> Result<()>
    where
        I: IntoIterator<Item = &'a String>,
    {
        for path in paths {
            let Some(key) = denied_file_parent_key(path)? else {
                continue;
            };
            map.insert(key, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate denied_files_in_dir entry '{}' dev={} ino={} in {}: {}",
                    path,
                    key.dev,
                    key.ino,
                    object_path,
                    e
                )
            })?;
        }
        Ok(())
    }

    /// Precise per-file key for a denied *file* path whose parent directory
    /// exists and resolves at load time: `(parent dev, parent ino, basename)`.
    /// Returns `None` for existing directories (handled by `denied_dir_inodes`),
    /// relative paths, empty leaves, or paths whose parent does not resolve to a
    /// directory — those fall back to the basename-only `denied_basenames` map so
    /// coverage never regresses (JG #60).
    fn denied_file_parent_key(path: &str) -> Result<Option<DirFileKey>> {
        let trimmed = path.trim().trim_end_matches('/');
        // Only an absolute path has an unambiguous resolvable parent directory.
        if !trimmed.starts_with('/') || denied_entry_is_existing_dir(trimmed) {
            return Ok(None);
        }
        let leaf = filesystem_policy_leaf(trimmed);
        if leaf.is_empty() {
            return Ok(None);
        }
        let Some(parent) = std::path::Path::new(trimmed).parent() else {
            return Ok(None);
        };
        let Ok(metadata) = std::fs::metadata(parent) else {
            return Ok(None);
        };
        if !metadata.is_dir() {
            return Ok(None);
        }
        Ok(Some(DirFileKey {
            dev: kernel_dev_from_stat(metadata.dev()),
            ino: metadata.ino(),
            name: name_to_key_bytes(leaf),
        }))
    }

    fn name_to_key_bytes(name: &str) -> [u8; JG_MAX_RESOURCE_LEN] {
        let mut out = [0u8; JG_MAX_RESOURCE_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(JG_MAX_RESOURCE_LEN.saturating_sub(1));
        out[..len].copy_from_slice(&bytes[..len]);
        out
    }

    fn denied_paths_for_object<'a>(policy: &'a PolicyConfig, object_path: &str) -> Vec<&'a String> {
        if object_path.contains("jg_inode_create") {
            return policy
                .agent_nodes
                .values()
                .flat_map(|node| node.denied_write_paths.iter())
                .collect();
        }
        if object_path.contains("jg_inode_unlink") {
            return policy
                .agent_nodes
                .values()
                .flat_map(|node| node.denied_unlink_paths.iter())
                .collect();
        }
        Vec::new()
    }

    fn denied_dir_inode(path: &str) -> Result<Option<InodeKey>> {
        let trimmed = path.trim();
        if trimmed.is_empty() || !trimmed.contains('/') {
            return Ok(None);
        }

        let configured = std::path::Path::new(trimmed);
        if let Ok(metadata) = std::fs::metadata(configured) {
            if !metadata.is_dir() {
                return Ok(None);
            }
            return Ok(Some(InodeKey {
                dev: kernel_dev_from_stat(metadata.dev()),
                ino: metadata.ino(),
            }));
        }

        Ok(None)
    }

    /// Re-encode a userspace `st_dev` (glibc bit layout) into the kernel-internal
    /// `dev_t` the BPF hook reads from `inode->i_sb->s_dev`: `(major << 20) | minor`
    /// (MINORBITS = 20). glibc and the kernel encode major/minor differently, so a
    /// raw `st_dev` would not match `s_dev`; decode and rebuild in kernel format.
    fn kernel_dev_from_stat(st_dev: u64) -> u64 {
        let major = libc::major(st_dev) as u64;
        let minor = libc::minor(st_dev) as u64;
        (major << 20) | (minor & 0xf_ffff)
    }

    fn denied_entry_is_existing_dir(path: &str) -> bool {
        let trimmed = path.trim();
        !trimmed.is_empty()
            && trimmed.contains('/')
            && std::fs::metadata(trimmed)
                .map(|metadata| metadata.is_dir())
                .unwrap_or(false)
    }

    fn filesystem_policy_leaf(path: &str) -> &str {
        let trimmed = path.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return "";
        }
        std::path::Path::new(trimmed)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(trimmed)
    }

    fn ipv4_policy_key(entry: &str) -> Option<u32> {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return None;
        }
        let host = trimmed
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(trimmed);
        host.parse::<Ipv4Addr>()
            .ok()
            .map(|addr| u32::from_ne_bytes(addr.octets()))
    }

    fn empty_path_key() -> PathKey {
        PathKey {
            path: [0; JG_MAX_RESOURCE_LEN],
        }
    }

    fn path_key(path: &str) -> PathKey {
        let mut key = empty_path_key();
        let bytes = path.trim().as_bytes();
        let len = bytes.len().min(JG_MAX_RESOURCE_LEN.saturating_sub(1));
        key.path[..len].copy_from_slice(&bytes[..len]);
        key
    }
}
