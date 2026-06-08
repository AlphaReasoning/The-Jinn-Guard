// ts_cli/src/ebpf_monitor.rs — eBPF/LSM backend types and loader.
//
// The `LsmRequest`, `LsmRequestType`, `Verdict`, and `VerdictPayload` types are
// always compiled (they're used in the feature-gated verdict loop in main.rs).
//
// The `aya_backend` module is only compiled with `--features kernel_telemetry`.

// ---------------------------------------------------------------------------
// Shared event types (always compiled)
// ---------------------------------------------------------------------------

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
    pub family: u16,
    /// Raw resource name as reported by the kernel (filename only for inode ops).
    pub resource: String,
    /// Best-effort full path resolved from /proc/[pid]/cwd + resource.
    /// Populated in the verdict loop before policy evaluation.
    pub resolved_path: Option<String>,
    pub payload_preview: Vec<u8>,
}

impl LsmRequest {
    /// Attempt to resolve the full path for inode operations by reading
    /// /proc/[pid]/cwd and prepending it to the raw resource filename.
    /// Falls back to resource if /proc resolution fails.
    pub fn resolve_path(&mut self) {
        if matches!(
            self.req_type,
            LsmRequestType::InodeCreate | LsmRequestType::InodeUnlink
        ) {
            if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", self.pid)) {
                // Only prepend cwd if resource doesn't already look like a full path.
                let full = if self.resource.starts_with('/') {
                    self.resource.clone()
                } else {
                    format!("{}/{}", cwd.display(), self.resource)
                };
                self.resolved_path = Some(full);
                return;
            }
        }
        // For non-inode ops, resolved_path stays None (caller uses resource).
    }

    /// Return the effective path for policy evaluation:
    /// resolved_path if available, otherwise resource.
    pub fn effective_path(&self) -> &str {
        self.resolved_path.as_deref().unwrap_or(&self.resource)
    }
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
    use crate::PolicyConfig;
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
    const BOOTSTRAP_ALLOWED_EXECUTABLES: &[&str] = &[
        "/usr/bin/sudo",
        "/usr/bin/systemctl",
        "/usr/bin/journalctl",
        "/usr/bin/bash",
        "/bin/bash",
        "/usr/bin/env",
        "/usr/bin/clear",
        "/usr/bin/sleep",
    ];
    /// Policy path key used by BPF maps.
    /// Must match `struct jg_path_key` in `bpf/lsm/jg_common.h`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PathKey {
        path: [u8; JG_MAX_RESOURCE_LEN],
    }

    unsafe impl aya::Pod for PathKey {}

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
    }

    const _: [(); 320] = [(); std::mem::size_of::<RawLsmRequest>()];
    const _: [(); 0] = [(); std::mem::offset_of!(RawLsmRequest, cookie)];
    const _: [(); 8] = [(); std::mem::offset_of!(RawLsmRequest, pid)];
    const _: [(); 12] = [(); std::mem::offset_of!(RawLsmRequest, req_type)];
    const _: [(); 16] = [(); std::mem::offset_of!(RawLsmRequest, family)];
    const _: [(); 18] = [(); std::mem::offset_of!(RawLsmRequest, resource_path)];
    const _: [(); 146] = [(); std::mem::offset_of!(RawLsmRequest, _pad_after_resource)];
    const _: [(); 148] = [(); std::mem::offset_of!(RawLsmRequest, dest)];
    const _: [(); 256] = [(); std::mem::offset_of!(RawLsmRequest, payload_preview)];
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
                family: raw.family,
                resource,
                resolved_path: None,
                payload_preview,
            };
            // Attempt full-path resolution for inode operations.
            req.resolve_path();
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
        _bpf: Ebpf,
        object_path: &'static str,
        requests: RingBuf<MapData>,
        verdicts: AyaHashMap<MapData, u64, VerdictPayload>,
        runtime_controls: Option<AyaArray<MapData, u32>>,
        ipv4_denylist: Option<AyaHashMap<MapData, u32, u8>>,
        allowed_exec_paths: Option<AyaHashMap<MapData, PathKey, u8>>,
        denied_basenames: Option<AyaHashMap<MapData, PathKey, u8>>,
        denied_dir_inodes: Option<AyaHashMap<MapData, u64, u8>>,
    }

    /// The main user-space monitor for loading LSM hooks and handling requests.
    pub struct AyaLsmMonitor {
        objects: Vec<LoadedLsmObject>,
        pending_routes: StdHashMap<u64, usize>,
    }

    impl AyaLsmMonitor {
        pub fn load(safe_mode: bool) -> Result<Self> {
            let btf = Btf::from_sys_fs()
                .map_err(|e| anyhow!("aya: failed to load kernel BTF from sysfs: {}", e))?;

            let mut objects = Vec::new();
            for (object_path, prog_name, hook_name) in [
                (
                    "/usr/lib/jinnguard/lsm/jg_socket_connect.o",
                    "jg_socket_connect",
                    "socket_connect",
                ),
                (
                    "/usr/lib/jinnguard/lsm/jg_socket_sendmsg.o",
                    "jg_socket_sendmsg",
                    "socket_sendmsg",
                ),
                (
                    "/usr/lib/jinnguard/lsm/jg_bprm_check_security.o",
                    "jg_bprm_check_security",
                    "bprm_check_security",
                ),
                (
                    "/usr/lib/jinnguard/lsm/jg_inode_create.o",
                    "jg_inode_create",
                    "inode_create",
                ),
                (
                    "/usr/lib/jinnguard/lsm/jg_inode_unlink.o",
                    "jg_inode_unlink",
                    "inode_unlink",
                ),
            ] {
                objects.push(load_lsm_object(
                    object_path,
                    prog_name,
                    hook_name,
                    &btf,
                    safe_mode,
                )?);
            }

            if safe_mode {
                eprintln!("[safe-mode] LSM audit-only mode active; deny decisions disabled");
            }

            Ok(Self {
                objects,
                pending_routes: StdHashMap::new(),
            })
        }

        /// Populate in-kernel policy maps before hooks are used for enforcement.
        ///
        /// LSM hooks cannot sleep while waiting for a user-space decision, so the
        /// synchronous allow/deny path must consult maps that are already loaded.
        pub(crate) fn configure_policy(
            &mut self,
            policy: &PolicyConfig,
            safe_mode: bool,
        ) -> Result<()> {
            self.configure_runtime_controls(safe_mode)?;

            for object in &mut self.objects {
                if let Some(map) = object.ipv4_denylist.as_mut() {
                    configure_ipv4_denylist(map, policy, object.object_path)?;
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

        fn configure_runtime_controls(&mut self, safe_mode: bool) -> Result<()> {
            let control_value = if safe_mode { JG_CONTROL_AUDIT_ONLY } else { 0 };
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
            for (object_index, object) in self.objects.iter_mut().enumerate() {
                while let Some(bytes) = object.requests.next() {
                    if bytes.len() >= std::mem::size_of::<RawLsmRequest>() {
                        let raw_req: RawLsmRequest = unsafe {
                            std::ptr::read_unaligned(bytes.as_ptr() as *const RawLsmRequest)
                        };
                        match LsmRequest::try_from(raw_req) {
                            Ok(req) => {
                                self.pending_routes.insert(req.cookie, object_index);
                                parsed_requests.push(req);
                            }
                            Err(e) => eprintln!(
                                "[eBPF LSM] Error parsing raw request from {}: {}",
                                object.object_path, e
                            ),
                        }
                    }
                }
            }
            Ok(parsed_requests)
        }
    }

    fn load_lsm_object(
        object_path: &'static str,
        prog_name: &'static str,
        hook_name: &'static str,
        btf: &Btf,
        safe_mode: bool,
    ) -> Result<LoadedLsmObject> {
        let data = std::fs::read(object_path)
            .map_err(|e| anyhow!("Failed to read eBPF LSM object {}: {}", object_path, e))?;

        let mut bpf = Ebpf::load(&data)
            .map_err(|e| anyhow!("aya: failed to load eBPF LSM object {}: {}", object_path, e))?;

        {
            let prog: &mut Lsm = bpf
                .program_mut(prog_name)
                .ok_or_else(|| anyhow!("eBPF program '{}' not found in {}", prog_name, object_path))?
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

        let prog: &mut Lsm = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow!("eBPF program '{}' not found in {}", prog_name, object_path))?
            .try_into()?;
        prog.attach()?;
        println!(
            "[eBPF LSM] Attached '{}' from '{}' to '{}' hook.",
            prog_name, object_path, hook_name
        );

        let requests = RingBuf::try_from(
            bpf.take_map("requests")
                .ok_or_else(|| anyhow!("eBPF map 'requests' not found in {}", object_path))?,
        )?;

        let verdicts: AyaHashMap<_, u64, VerdictPayload> = AyaHashMap::try_from(
            bpf.take_map("verdicts")
                .ok_or_else(|| anyhow!("eBPF map 'verdicts' not found in {}", object_path))?,
        )?;

        let ipv4_denylist = optional_hash_map(&mut bpf, "ipv4_denylist", object_path)?;
        let allowed_exec_paths = optional_hash_map(&mut bpf, "allowed_exec_paths", object_path)?;
        let denied_basenames = optional_hash_map(&mut bpf, "denied_basenames", object_path)?;
        let denied_dir_inodes = optional_hash_map(&mut bpf, "denied_dir_inodes", object_path)?;

        Ok(LoadedLsmObject {
            _bpf: bpf,
            object_path,
            requests,
            verdicts,
            runtime_controls,
            ipv4_denylist,
            allowed_exec_paths,
            denied_basenames,
            denied_dir_inodes,
        })
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

    fn configure_allowed_exec_paths(
        map: &mut AyaHashMap<MapData, PathKey, u8>,
        policy: &PolicyConfig,
        object_path: &str,
    ) -> Result<()> {
        for path in BOOTSTRAP_ALLOWED_EXECUTABLES {
            insert_allowed_exec_path(map, path, object_path)?;
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
        map: &mut AyaHashMap<MapData, u64, u8>,
        paths: I,
        object_path: &str,
    ) -> Result<()>
    where
        I: IntoIterator<Item = &'a String>,
    {
        for path in paths {
            let Some(ino) = denied_dir_inode(path)? else {
                continue;
            };
            map.insert(ino, 1, 0).map_err(|e| {
                anyhow!(
                    "Failed to populate denied_dir_inodes entry '{}' ino={} in {}: {}",
                    path,
                    ino,
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

    fn denied_dir_inode(path: &str) -> Result<Option<u64>> {
        let trimmed = path.trim();
        if trimmed.is_empty() || !trimmed.contains('/') {
            return Ok(None);
        }

        let configured = std::path::Path::new(trimmed);
        if let Ok(metadata) = std::fs::metadata(configured) {
            return Ok(metadata.is_dir().then_some(metadata.ino()));
        }

        Ok(None)
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
