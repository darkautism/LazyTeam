use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

const EXEC_ARG: &str = "__lazyteam-sandbox-exec";
const CONTAINER_EXEC_ARG: &str = "__lazyteam-container-exec";
const SIGNAL_PROBE_ARG: &str = "__lazyteam-sandbox-signal-probe";
const SPEC_ENV: &str = "LAZYTEAM_SANDBOX_SPEC";
const UID_ISOLATION_ENV: &str = "LAZYTEAM_SANDBOX_UID";
const SANDBOX_UID_MIN: u32 = 20_000;
const SANDBOX_UID_MAX: u32 = 59_999;
const LOCAL_ARTIFACT_DIRS: &[&str] = &["target", "node_modules", "__pycache__", ".pytest_cache", ".venv"];
/// Image-native paths that may be visible to agents when present in the frozen
/// container rootfs. These paths join the same canonical read_only policy
/// consumed by every filesystem enforcement backend; they are not host
/// overlays and must never grow a backend-specific allowlist.
const CONTAINER_NATIVE_READ_ONLY: &[&str] = &["/opt/lazyteam"];
// Minimal Linux runtime metadata used by Bun/JSC and similar runtimes. Keep
// these narrow: exposing all of /proc would let an agent inspect sibling Host
// processes running under the same uid.
const RUNTIME_PROC_READ_ONLY: &[&str] = &[
    "/proc/self",
    "/proc/version",
    "/proc/sys/vm/overcommit_memory",
    "/proc/sys/vm/mmap_min_addr",
];
const RUNTIME_SYS_READ_ONLY: &[&str] = &[
    "/sys/devices/system/cpu/online",
    "/sys/fs/cgroup/cpu.max",
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory.high",
    "/sys/kernel/mm/transparent_hugepage/enabled",
];
const CONTAINER_RUSTUP_HOME: &str = "/opt/lazyteam/rustup";
const CONTAINER_CARGO_BIN: &str = "/opt/lazyteam/cargo/bin";

fn container_managed_rust_paths(container_rootfs: Option<&Path>) -> Option<(PathBuf, PathBuf)> {
    let rootfs = container_rootfs?;
    let rustup_home = PathBuf::from(CONTAINER_RUSTUP_HOME);
    let cargo_bin = PathBuf::from(CONTAINER_CARGO_BIN);
    let rustup_image = rootfs.join(rustup_home.strip_prefix("/").ok()?);
    let cargo_image = rootfs.join(cargo_bin.strip_prefix("/").ok()?).join("cargo");
    (rustup_image.is_dir() && cargo_image.is_file()).then_some((rustup_home, cargo_bin))
}

fn host_visible_managed_rust_paths(rootfs: Option<&Path>) -> Option<(PathBuf, PathBuf)> {
    let rootfs = rootfs?;
    let rustup_home = rootfs.join(CONTAINER_RUSTUP_HOME.trim_start_matches('/'));
    let cargo_bin = rootfs.join(CONTAINER_CARGO_BIN.trim_start_matches('/'));
    (rustup_home.is_dir() && cargo_bin.join("cargo").is_file()).then_some((rustup_home, cargo_bin))
}

#[cfg(target_os = "linux")]
fn nested_mount_namespace_available() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    std::process::Command::new("/usr/bin/unshare")
        .args(["--mount", "--", "/bin/true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(target_os = "linux"))]
fn nested_mount_namespace_available() -> bool { false }

fn managed_rust_version(line: &str) -> Option<(u64, u64, u64)> {
    let version = line.split_whitespace().nth(1)?;
    let mut parts = version.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next().unwrap_or("0").parse().ok()?,
    ))
}

fn add_container_native_read_only(
    read_only: &mut BTreeSet<PathBuf>,
    container_rootfs: Option<&Path>,
) {
    let Some(rootfs) = container_rootfs else { return; };
    for path in CONTAINER_NATIVE_READ_ONLY {
        let absolute = Path::new(path);
        let Ok(relative) = absolute.strip_prefix("/") else { continue; };
        if rootfs.join(relative).exists() {
            read_only.insert(absolute.to_path_buf());
        }
    }
}

fn add_runtime_metadata_read_only(
    read_only: &mut BTreeSet<PathBuf>,
    container_read_only: &mut BTreeSet<PathBuf>,
    container_rootfs: Option<&Path>,
) {
    // /proc is freshly mounted before Landlock in nested-container mode, and
    // refers to the sandbox launcher itself in outer-container mode. Preserve
    // the magic /proc/self path rather than canonicalizing it in the Host.
    for path in RUNTIME_PROC_READ_ONLY {
        read_only.insert(PathBuf::from(path));
    }

    // The nested rootfs does not mount sysfs. Bind only the exact metadata
    // files that exist on the Host, read-only. In outer-container mode the same
    // paths are simply admitted by Landlock.
    for path in RUNTIME_SYS_READ_ONLY {
        let absolute = PathBuf::from(path);
        if !absolute.exists() {
            continue;
        }
        read_only.insert(absolute.clone());
        if container_rootfs.is_some() {
            container_read_only.insert(absolute);
        }
    }
}

#[cfg(target_os = "linux")]
fn sandbox_uid_key(workspace: &Path) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in workspace.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(target_os = "linux")]
fn sandbox_uid_for_workspace(uid_dir: &Path, workspace: &Path) -> anyhow::Result<u32> {
    use std::{fs::OpenOptions, os::fd::AsRawFd};
    use std::os::unix::fs::MetadataExt;

    std::fs::create_dir_all(uid_dir).context("create sandbox uid directory")?;
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(uid_dir.join(".lock"))
        .context("open sandbox uid allocation lock")?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        bail!("lock sandbox uid allocator failed: {}", std::io::Error::last_os_error());
    }

    let workspace_text = workspace.to_string_lossy().to_string();
    let key = sandbox_uid_key(workspace);
    let mapping_path = uid_dir.join(format!("{key}.json"));
    if mapping_path.exists() {
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&mapping_path).context("read sandbox uid mapping")?,
        )
        .context("parse sandbox uid mapping")?;
        let mapped_workspace = value.get("workspace").and_then(serde_json::Value::as_str)
            .context("sandbox uid mapping missing workspace")?;
        let uid = value.get("uid").and_then(serde_json::Value::as_u64)
            .context("sandbox uid mapping missing uid")?;
        if mapped_workspace != workspace_text {
            bail!("sandbox uid mapping hash collision for {}", workspace.display());
        }
        let uid: u32 = uid.try_into().context("sandbox uid mapping out of range")?;
        if !(SANDBOX_UID_MIN..=SANDBOX_UID_MAX).contains(&uid) {
            bail!("sandbox uid mapping {uid} is outside reserved range");
        }
        return Ok(uid);
    }

    let mut used = BTreeSet::new();
    used.insert(unsafe { libc::geteuid() });
    if let Some(state_dir) = uid_dir.parent() {
        if let Ok(metadata) = std::fs::metadata(state_dir) {
            used.insert(metadata.uid());
        }
    }
    for entry in std::fs::read_dir(uid_dir).context("scan sandbox uid mappings")? {
        let entry = entry?;
        if entry.path().extension() != Some(OsStr::new("json")) {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else { continue; };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else { continue; };
        if let Some(uid) = value.get("uid").and_then(serde_json::Value::as_u64)
            .and_then(|uid| u32::try_from(uid).ok())
        {
            used.insert(uid);
        }
    }
    let uid = (SANDBOX_UID_MIN..=SANDBOX_UID_MAX)
        .find(|uid| !used.contains(uid))
        .context("sandbox uid pool exhausted")?;
    let mapping = serde_json::json!({"workspace": workspace_text, "uid": uid});
    let temp_path = uid_dir.join(format!(".{key}-{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&temp_path, serde_json::to_vec(&mapping)?)
        .context("write sandbox uid mapping")?;
    std::fs::rename(&temp_path, &mapping_path).context("publish sandbox uid mapping")?;
    Ok(uid)
}

#[cfg(not(target_os = "linux"))]
fn sandbox_uid_for_workspace(_uid_dir: &Path, _workspace: &Path) -> anyhow::Result<u32> {
    bail!("sandbox uid isolation requires Linux")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxSpec {
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    working_dir: PathBuf,
    namespace_root_base: PathBuf,
    container_rootfs: Option<PathBuf>,
    container_read_only: Vec<PathBuf>,
    #[serde(default)]
    nested_read_only: Vec<PathBuf>,
    #[serde(default)]
    trusted_container_daemon: bool,
    #[serde(default)]
    sandbox_uid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AgentSandbox {
    state_dir: PathBuf,
    pi_config_dir: PathBuf,
    home_dir: PathBuf,
    cargo_home: PathBuf,
    cargo_target_dir: PathBuf,
    tmp_dir: PathBuf,
    probe_dir: PathBuf,
    namespace_root_base: PathBuf,
    read_only: Vec<PathBuf>,
    path: OsString,
    rustup_home: Option<PathBuf>,
    container_rootfs: Option<PathBuf>,
    container_read_only: Vec<PathBuf>,
    trusted_container_daemon: bool,
    sandbox_uid_dir: PathBuf,
    launcher_exe: PathBuf,
}

impl AgentSandbox {
    pub async fn prepare(state_dir: &Path, pi_bin: &str, container_rootfs: Option<&Path>) -> anyhow::Result<Self> {
        let state_dir = canonical_dir(state_dir).context("canonicalize worker state directory")?;
        let requested_container_rootfs = container_rootfs.map(canonical_dir).transpose().context("canonicalize agent rootfs")?;
        let container_rootfs = if requested_container_rootfs.is_some() && nested_mount_namespace_available() {
            requested_container_rootfs.clone()
        } else {
            if requested_container_rootfs.is_some() {
                tracing::warn!(
                    uid = unsafe { libc::geteuid() },
                    "nested mount namespace unavailable; using outer-container Landlock/seccomp sandbox"
                );
            }
            None
        };
        // Trust is a property of the worker daemon deployment, not of whether
        // the optional nested rootfs mount namespace is available. The outer-
        // container Landlock fallback still runs inside the same trusted worker
        // container and can use per-sandbox Unix credentials for safe child control.
        let trusted_container_daemon = std::env::var_os("LAZYTEAM_TRUSTED_CONTAINER_DAEMON")
            .is_some_and(|value| value == "1");
        let pi_config_dir = state_dir.join("pi-agent");
        let home_dir = state_dir.join("agent-home");
        let cargo_home = state_dir.join("agent-cache").join("cargo");
        let cargo_target_dir = state_dir.join("agent-cache").join("target");
        let tmp_dir = state_dir.join("agent-tmp");
        let probe_dir = state_dir.join("agent-probe");
        let namespace_root_base = state_dir.join("sandbox-roots");
        let sandbox_uid_dir = state_dir.join("sandbox-uids");
        if namespace_root_base.exists() {
            tokio::fs::remove_dir_all(&namespace_root_base).await?;
        }
        for dir in [&home_dir, &cargo_home, &cargo_target_dir, &tmp_dir, &probe_dir, &namespace_root_base, &sandbox_uid_dir] {
            tokio::fs::create_dir_all(dir).await?;
            set_private_dir(dir).await?;
        }
        tokio::fs::create_dir_all(&pi_config_dir).await?;
        // Sandboxed Pi runs under a per-workspace uid. Node's fs.existsSync()
        // uses access(2)-style checks that ignore CAP_DAC_OVERRIDE for a
        // non-root real uid, so a 0700 parent makes an existing auth.json look
        // absent even though direct reads work. Pi then creates "{}" and
        // silently erases the queued credential. Grant execute-only traversal
        // to other sandbox uids; auth.json itself remains 0600 and Landlock
        // still limits visibility to this worker's Pi config path.
        set_traversable_private_dir(&pi_config_dir).await?;
        let host_path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin"));
        let mut path = if container_rootfs.is_some() {
            OsString::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        } else {
            host_path.clone()
        };
        let mut read_only = BTreeSet::new();
        let mut container_read_only = BTreeSet::new();
        for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
            if let Ok(path) = std::fs::canonicalize(path) {
                read_only.insert(path);
            }
        }
        for path in ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"] {
            if container_rootfs.is_some() {
                read_only.insert(PathBuf::from(path));
            } else if let Ok(path) = std::fs::canonicalize(path) {
                read_only.insert(path);
            }
        }
        if container_rootfs.is_none() {
            let host_home = std::env::var_os("HOME").map(PathBuf::from).and_then(|path| std::fs::canonicalize(path).ok());
            for dir in std::env::split_paths(&host_path) {
                if let Ok(dir) = std::fs::canonicalize(dir) {
                    let broad_home = host_home.as_ref().is_some_and(|home| dir == *home || home.starts_with(&dir));
                    if !broad_home {
                        read_only.insert(dir);
                    }
                }
            }
        }

        // Container-native image content participates in the exact same
        // filesystem policy as every other read-only path when the nested rootfs
        // can be entered. NAS/container runtimes that deny CLONE_NEWNS instead
        // use the outer container plus the same Landlock/seccomp policy.
        add_container_native_read_only(&mut read_only, container_rootfs.as_deref());
        add_runtime_metadata_read_only(
            &mut read_only,
            &mut container_read_only,
            container_rootfs.as_deref(),
        );

        // Managed Rust remains usable in both layouts. In nested-rootfs mode the
        // agent sees /opt/lazyteam directly; in outer-container fallback mode use
        // the host-visible path inside the extracted rootfs and allow it read-only.
        let container_rust = container_managed_rust_paths(container_rootfs.as_deref());
        let fallback_rust = container_rootfs.is_none()
            .then(|| host_visible_managed_rust_paths(requested_container_rootfs.as_deref()))
            .flatten();
        if let Some((rustup_home, cargo_bin)) = fallback_rust.as_ref() {
            read_only.insert(rustup_home.clone());
            read_only.insert(cargo_bin.clone());
        }
        let managed_rust = container_rust.as_ref().or(fallback_rust.as_ref());
        if let Some((_, cargo_bin)) = managed_rust {
            let mut paths = vec![cargo_bin.clone()];
            paths.extend(std::env::split_paths(&path));
            path = std::env::join_paths(paths).context("compose agent PATH with managed Rust")?;
        }

        if let Some(program) = resolve_program(pi_bin, &host_path) {
            // A managed Pi runtime uses a stable symlink under state/pi-runtime
            // and atomically switches that link after a fully installed update.
            // Admit the stable runtime root up front so a later daily update can
            // point at a new version without rebuilding the sandbox policy.
            if program.starts_with(&state_dir) {
                if let Some(runtime_root) = program.parent().and_then(Path::parent) {
                    read_only.insert(runtime_root.to_path_buf());
                    if container_rootfs.is_some() {
                        container_read_only.insert(runtime_root.to_path_buf());
                    }
                }
            }
            if let Ok(target) = std::fs::canonicalize(&program) {
                let runtime_root = common_ancestor(&program, &target).filter(|root| path_depth(root) >= 3)
                    .or_else(|| program.parent().map(Path::to_path_buf));
                if let Some(root) = runtime_root {
                    read_only.insert(root.clone());
                    if container_rootfs.is_some() {
                        container_read_only.insert(root.clone());
                        if let Some(bin) = program.parent() {
                            let mut paths = vec![bin.to_path_buf()];
                            paths.extend(std::env::split_paths(&path));
                            path = std::env::join_paths(paths).context("compose agent container PATH")?;
                        }
                    }
                }
            }
        }

        let host_cargo_bin = container_rootfs.is_none().then(|| std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
            .map(|path| path.join("bin"))
            .filter(|path| path.exists())
            .and_then(|path| std::fs::canonicalize(path).ok())).flatten();
        if let Some(path) = host_cargo_bin {
            read_only.insert(path);
        }

        let rustup_home = if let Some((rustup_home, _)) = container_rust {
            Some(rustup_home)
        } else if let Some((rustup_home, _)) = fallback_rust {
            Some(rustup_home)
        } else if container_rootfs.is_none() {
            std::env::var_os("RUSTUP_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
                .filter(|path| path.exists())
                .and_then(|path| std::fs::canonicalize(path).ok())
        } else {
            None
        };
        if container_rootfs.is_none() {
            if let Some(path) = &rustup_home {
                read_only.insert(path.clone());
            }
        }

        let launcher_exe = std::env::var_os("LAZYTEAM_SANDBOX_LAUNCHER")
            .map(PathBuf::from)
            .unwrap_or(std::env::current_exe().context("resolve sandbox launcher executable")?);
        let launcher_exe = std::fs::canonicalize(&launcher_exe)
            .with_context(|| format!("canonicalize sandbox launcher {}", launcher_exe.display()))?;
        read_only.insert(launcher_exe.clone());
        let sandbox = Self {
            state_dir,
            pi_config_dir,
            home_dir,
            cargo_home,
            cargo_target_dir,
            tmp_dir,
            probe_dir,
            namespace_root_base,
            read_only: read_only.into_iter().collect(),
            path,
            rustup_home,
            container_rootfs,
            container_read_only: container_read_only.into_iter().collect(),
            trusted_container_daemon,
            sandbox_uid_dir,
            launcher_exe,
        };
        sandbox.probe().await?;
        Ok(sandbox)
    }

    pub fn probe_workspace(&self) -> &Path { &self.probe_dir }

    pub fn agent_workspace(&self, task_id: uuid::Uuid) -> PathBuf {
        self.state_dir.join("agent-workspaces").join(task_id.to_string())
    }

    pub fn reviewer_workspace(&self, review_id: uuid::Uuid) -> PathBuf {
        self.state_dir.join("agent-review-workspaces").join(review_id.to_string())
    }

    pub fn diagnostic_summary(&self) -> &'static str {
        if self.container_rootfs.is_some() {
            "ready: nested Ubuntu rootfs + filesystem isolation + seccomp denylist"
        } else {
            "ready: outer-container Landlock/rootless isolation + seccomp denylist"
        }
    }

    pub async fn store_pi_api_key(&self, provider: &str, api_key: &str) -> anyhow::Result<()> {
        let provider = provider.trim();
        if provider.is_empty() || api_key.trim().is_empty() {
            bail!("provider and API key are required");
        }
        let auth_path = self.pi_config_dir.join("auth.json");
        let mut root = match tokio::fs::read(&auth_path).await {
            Ok(bytes) if !bytes.is_empty() => serde_json::from_slice::<serde_json::Value>(&bytes)
                .context("parse isolated Pi auth.json")?,
            Ok(_) => serde_json::json!({}),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
            Err(error) => return Err(error).context("read isolated Pi auth.json"),
        };
        let object = root.as_object_mut().context("isolated Pi auth.json must contain a JSON object")?;
        object.insert(provider.to_string(), serde_json::json!({"type":"api_key","key":api_key}));
        let tmp_path = self.pi_config_dir.join(format!("auth.json.tmp-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&tmp_path, serde_json::to_vec_pretty(&root)?).await?;
        set_private_file(&tmp_path).await?;
        tokio::fs::rename(&tmp_path, &auth_path).await?;
        set_private_file(&auth_path).await?;
        Ok(())
    }

    pub fn command(&self, program: &str, workspace: &Path, session_dir: Option<&Path>) -> anyhow::Result<Command> {
        let workspace = canonical_dir(workspace).context("canonicalize agent workspace")?;
        let mut read_write = vec![
            workspace.clone(),
            self.pi_config_dir.clone(),
            self.home_dir.clone(),
            self.cargo_home.clone(),
            self.cargo_target_dir.clone(),
            self.tmp_dir.clone(),
        ];
        if let Some(session_dir) = session_dir {
            read_write.push(canonical_dir(session_dir).context("canonicalize Pi session directory")?);
        }
        for device in ["/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"] {
            if let Ok(path) = std::fs::canonicalize(device) {
                read_write.push(path);
            }
        }

        let nested_read_only = workspace.join(".git");
        let nested_read_only = nested_read_only.exists().then_some(nested_read_only).into_iter().collect();
        let sandbox_uid = if self.trusted_container_daemon {
            Some(sandbox_uid_for_workspace(&self.sandbox_uid_dir, &workspace)?)
        } else {
            None
        };
        let spec = SandboxSpec {
            read_only: self.read_only.clone(),
            read_write,
            working_dir: workspace.clone(),
            namespace_root_base: self.namespace_root_base.clone(),
            container_rootfs: self.container_rootfs.clone(),
            container_read_only: self.container_read_only.clone(),
            nested_read_only,
            trusted_container_daemon: self.trusted_container_daemon,
            sandbox_uid,
        };
        let mut command = Command::new(&self.launcher_exe);
        command.arg(if self.container_rootfs.is_some() { CONTAINER_EXEC_ARG } else { EXEC_ARG }).arg(program);
        command.current_dir(&workspace);
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        command.env_clear();
        command.env(SPEC_ENV, serde_json::to_string(&spec)?);
        command.env("PATH", &self.path);
        command.env("HOME", &self.home_dir);
        command.env("PI_CODING_AGENT_DIR", &self.pi_config_dir);
        command.env("CARGO_HOME", &self.cargo_home);
        command.env("CARGO_TARGET_DIR", &self.cargo_target_dir);
        command.env("XDG_CACHE_HOME", self.home_dir.join(".cache"));
        command.env("XDG_CONFIG_HOME", self.home_dir.join(".config"));
        command.env("TMPDIR", &self.tmp_dir);
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        command.env("GIT_CONFIG_GLOBAL", "/dev/null");
        command.env("GIT_OPTIONAL_LOCKS", "0");
        command.env("GIT_ASKPASS", "/bin/false");
        command.env("SSH_ASKPASS", "/bin/false");
        command.env("GIT_SSH_COMMAND", "/bin/false");
        if let Some(parent) = workspace.parent() {
            command.env("GIT_CEILING_DIRECTORIES", parent);
        }
        if let Some(rustup_home) = &self.rustup_home {
            command.env("RUSTUP_HOME", rustup_home);
        }
        for key in ["LANG", "LC_ALL", "TERM", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        Ok(command)
    }

    pub async fn probe_managed_rust_toolchain(&self) -> anyhow::Result<String> {
        let mut command = self.command("/bin/sh", &self.probe_dir, None)?;
        command.arg("-c").arg("rustc --version && cargo --version");
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let output = command.output().await.context("probe managed Rust toolchain through agent sandbox")?;
        if !output.status.success() {
            bail!(
                "managed Rust toolchain is not executable through the agent sandbox: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8(output.stdout).context("managed Rust probe returned non-UTF8 output")?;
        let mut lines = stdout.lines();
        let rustc = lines.next().context("managed Rust probe did not return rustc version")?;
        let cargo = lines.next().context("managed Rust probe did not return cargo version")?;
        for (name, line) in [("rustc", rustc), ("cargo", cargo)] {
            let version = managed_rust_version(line)
                .with_context(|| format!("parse managed {name} version from {line:?}"))?;
            if version < (1, 85, 0) {
                bail!("managed {name} {}.{}.{} is below the Rust 1.85 / edition-2024 floor", version.0, version.1, version.2);
            }
        }
        Ok(stdout.trim().to_string())
    }

    async fn probe(&self) -> anyhow::Result<()> {
        let mut command = self.command("/bin/true", &self.probe_dir, None)?;
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        let output = command.output().await.context("spawn embedded sandbox capability probe")?;
        if !output.status.success() {
            bail!(
                "agent sandbox unavailable (fail-closed): {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let launcher = self.launcher_exe.to_str().context("sandbox launcher path is not UTF-8")?;
        let mut command = self.command(launcher, &self.probe_dir, None)?;
        command.arg(SIGNAL_PROBE_ARG);
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        let output = command.output().await.context("probe sandbox process isolation")?;
        if !output.status.success() {
            bail!(
                "agent sandbox process-isolation probe failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

pub fn maybe_enter_daemon_user_namespace() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let Some(uid_raw) = std::env::var_os("LAZYTEAM_DAEMON_USERNS_UID") else { return Ok(()); };
        let gid_raw = std::env::var_os("LAZYTEAM_DAEMON_USERNS_GID")
            .context("LAZYTEAM_DAEMON_USERNS_GID is required with LAZYTEAM_DAEMON_USERNS_UID")?;
        let outer_uid: u32 = uid_raw.to_string_lossy().parse().context("parse daemon user namespace uid")?;
        let outer_gid: u32 = gid_raw.to_string_lossy().parse().context("parse daemon user namespace gid")?;
        if unsafe { libc::geteuid() } != 0 {
            bail!("daemon user namespace bootstrap requires root entrypoint before remapping");
        }
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            bail!("unshare daemon user namespace failed: {}", std::io::Error::last_os_error());
        }
        let map_gid = prepare_gid_mapping("daemon user namespace")?;
        fs::write("/proc/self/uid_map", format!("0 {outer_uid} 1\n"))
            .context("write daemon user namespace uid_map")?;
        if map_gid {
            fs::write("/proc/self/gid_map", format!("0 {outer_gid} 1\n"))
                .context("write daemon user namespace gid_map")?;
            if unsafe { libc::setresgid(0, 0, 0) } != 0 {
                bail!("setresgid inside daemon user namespace failed: {}", std::io::Error::last_os_error());
            }
        }
        if unsafe { libc::setresuid(0, 0, 0) } != 0 {
            bail!("setresuid inside daemon user namespace failed: {}", std::io::Error::last_os_error());
        }
        unsafe {
            std::env::remove_var("LAZYTEAM_DAEMON_USERNS_UID");
            std::env::remove_var("LAZYTEAM_DAEMON_USERNS_GID");
        }
    }
    Ok(())
}

pub fn maybe_handle_entrypoint() -> Option<anyhow::Result<()>> {
    let mut args = std::env::args_os();
    let _ = args.next();
    let mode = args.next()?;
    if mode == OsStr::new(EXEC_ARG) {
        return Some(sandbox_exec(args.collect(), false));
    }
    if mode == OsStr::new(CONTAINER_EXEC_ARG) {
        return Some(sandbox_exec(args.collect(), true));
    }
    if mode == OsStr::new(SIGNAL_PROBE_ARG) {
        return Some(sandbox_signal_probe());
    }
    None
}

#[cfg(target_os = "linux")]
fn sandbox_signal_probe() -> anyhow::Result<()> {
    let own_pid = unsafe { libc::getpid() };
    let own_tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
    if unsafe { libc::syscall(libc::SYS_tgkill, own_pid, own_tid, 0) } != 0 {
        bail!("tgkill(2) self-thread probe was blocked: {}", std::io::Error::last_os_error());
    }

    if let Some(expected_uid) = std::env::var_os(UID_ISOLATION_ENV) {
        let expected_uid: u32 = expected_uid
            .to_string_lossy()
            .parse()
            .context("parse sandbox uid isolation marker")?;
        if unsafe { libc::geteuid() } != expected_uid {
            bail!(
                "sandbox uid isolation probe ran as uid {}, expected {expected_uid}",
                unsafe { libc::geteuid() }
            );
        }

        let parent = unsafe { libc::getppid() };
        if unsafe { libc::kill(parent, 0) } == 0 {
            bail!("sandbox uid isolation unexpectedly allowed signalling parent pid {parent}");
        }
        let parent_error = std::io::Error::last_os_error();
        if parent_error.raw_os_error() != Some(libc::EPERM) {
            bail!("sandbox parent signal probe returned {parent_error}, expected EPERM from uid isolation");
        }

        let child = unsafe { libc::fork() };
        if child < 0 {
            bail!("fork sandbox signal probe child failed: {}", std::io::Error::last_os_error());
        }
        if child == 0 {
            unsafe { libc::pause(); }
            unreachable!();
        }
        if unsafe { libc::kill(child, libc::SIGKILL) } != 0 {
            bail!("kill(2) sandbox child probe failed: {}", std::io::Error::last_os_error());
        }
        let status = wait_for_pid(child, "sandbox signal probe child")?;
        if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
            bail!("sandbox child signal probe returned unexpected wait status {status}");
        }
        return Ok(());
    }

    let parent = unsafe { libc::getppid() };
    if unsafe { libc::syscall(libc::SYS_tgkill, parent, parent, 0) } == 0 {
        bail!("tgkill(2) unexpectedly reached parent pid {parent}");
    }
    let tgkill_error = std::io::Error::last_os_error();
    if tgkill_error.raw_os_error() != Some(libc::EPERM) {
        bail!("tgkill(2) parent probe returned {tgkill_error}, expected EPERM from seccomp");
    }

    if unsafe { libc::kill(parent, 0) } == 0 {
        bail!("kill(2) unexpectedly reached parent pid {parent}");
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EPERM) {
        bail!("kill(2) parent probe returned {error}, expected EPERM from seccomp");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn sandbox_signal_probe() -> anyhow::Result<()> {
    bail!("sandbox signal probe requires Linux")
}

fn sandbox_exec(mut args: Vec<OsString>, enter_container: bool) -> anyhow::Result<()> {
    if args.is_empty() {
        bail!("sandbox helper missing program");
    }
    let program = args.remove(0);
    let raw = std::env::var(SPEC_ENV).context("sandbox helper missing policy")?;
    let spec: SandboxSpec = serde_json::from_str(&raw).context("parse sandbox policy")?;

    if spec.trusted_container_daemon {
        let sandbox_uid = spec.sandbox_uid.context("trusted sandbox missing isolated uid")?;
        if enter_container {
            enter_agent_container(&spec)?;
        }
        enable_agent_no_new_privs()?;
        // Filesystem policy is installed while the trusted launcher still has
        // setup capabilities. Process signalling is then protected by Linux
        // credential checks: each logical sandbox has a distinct uid, while
        // descendants inherit that uid and retain normal kill/wait semantics.
        apply_policy(&spec, true)?;
        enter_sandbox_uid(sandbox_uid)?;
        unsafe { std::env::set_var(UID_ISOLATION_ENV, sandbox_uid.to_string()); }
        return exec_sandboxed_program(program, args);
    }

    if enter_container {
        enter_agent_container(&spec)?;
    }
    enable_agent_no_new_privs()?;
    apply_policy(&spec, false)?;
    drop_agent_capabilities()?;
    exec_sandboxed_program(program, args)
}

#[cfg(target_os = "linux")]
fn wait_for_pid(pid: libc::pid_t, label: &str) -> anyhow::Result<i32> {
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        bail!("wait for {label} failed: {}", std::io::Error::last_os_error());
    }
}

#[cfg(unix)]
fn exec_sandboxed_program(program: OsString, args: Vec<OsString>) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(program);
    command.args(args).env_remove(SPEC_ENV);
    let error = command.exec();
    Err(error).context("exec sandboxed agent")
}

#[cfg(not(unix))]
fn exec_sandboxed_program(_program: OsString, _args: Vec<OsString>) -> anyhow::Result<()> {
    bail!("embedded agent sandbox is only supported on Unix")
}

#[cfg(target_os = "linux")]
fn prepare_gid_mapping(context: &str) -> anyhow::Result<bool> {
    let path = Path::new("/proc/self/setgroups");
    if !path.exists() {
        return Ok(true);
    }
    let current = std::fs::read_to_string(path)
        .with_context(|| format!("read setgroups state for {context}"))?;
    match current.trim() {
        "deny" => Ok(true),
        "allow" => match std::fs::write(path, b"deny\n") {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
            Err(error) => Err(error).with_context(|| format!("disable setgroups for {context}")),
        },
        other => bail!("unexpected setgroups state for {context}: {other}"),
    }
}

#[cfg(target_os = "linux")]
fn root_in_outer_user_namespace() -> anyhow::Result<bool> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(false);
    }
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").context("read current user namespace uid_map")?;
    let mut fields = uid_map.lines().next().unwrap_or_default().split_whitespace();
    let inside = fields.next().and_then(|value| value.parse::<u64>().ok());
    let outside = fields.next().and_then(|value| value.parse::<u64>().ok());
    let length = fields.next().and_then(|value| value.parse::<u64>().ok());
    Ok(matches!((inside, outside, length), (Some(0), Some(host), Some(span)) if host != 0 || span != u32::MAX as u64))
}

#[cfg(target_os = "linux")]
fn enter_agent_container(spec: &SandboxSpec) -> anyhow::Result<()> {
    use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, ptr};

    let rootfs = spec.container_rootfs.as_ref().context("agent container rootfs is missing")?;
    if spec.trusted_container_daemon {
        if unsafe { libc::geteuid() } != 0 {
            bail!("trusted container daemon sandbox helper lost container uid 0");
        }
    } else if !root_in_outer_user_namespace()? {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            bail!("unshare agent container user namespace failed: {}", std::io::Error::last_os_error());
        }
        let map_gid = prepare_gid_mapping("agent container")?;
        fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).context("write agent container uid_map")?;
        if map_gid {
            fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).context("write agent container gid_map")?;
            if unsafe { libc::setresgid(0, 0, 0) } != 0 {
                bail!("setresgid inside agent container failed: {}", std::io::Error::last_os_error());
            }
        }
        if unsafe { libc::setresuid(0, 0, 0) } != 0 {
            bail!("setresuid inside agent container failed: {}", std::io::Error::last_os_error());
        }
    }
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        bail!("unshare agent container mount namespace failed: {}", std::io::Error::last_os_error());
    }

    let slash = CString::new("/")?;
    if unsafe {
        libc::mount(
            ptr::null(),
            slash.as_ptr(),
            ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            ptr::null(),
        )
    } != 0 {
        bail!("make agent container mounts private failed: {}", std::io::Error::last_os_error());
    }

    let rootfs_c = CString::new(rootfs.as_os_str().as_bytes())?;
    if unsafe {
        libc::mount(
            rootfs_c.as_ptr(),
            rootfs_c.as_ptr(),
            ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            ptr::null(),
        )
    } != 0 {
        bail!("bind agent rootfs failed: {}", std::io::Error::last_os_error());
    }

    // Create every bind target while the image is still writable. This vendor
    // kernel rejects making the root mount read-only after child mounts already exist.
    for source in spec.container_read_only.iter()
        .chain(spec.read_write.iter())
        .chain(spec.nested_read_only.iter())
        .chain(std::iter::once(&spec.namespace_root_base))
    {
        prepare_container_mountpoint(rootfs, source)?;
    }
    // Toolchains such as rustc/cargo resolve their own executable through
    // /proc/self/exe. The Ubuntu rootfs is a plain filesystem tree, so chroot
    // alone would otherwise leave /proc empty. Mount a fresh procfs inside the
    // agent's private mount namespace; it disappears with the sandbox process.
    fs::create_dir_all(rootfs.join("proc")).context("create agent proc mountpoint")?;

    // Freeze the image before layering any child mounts. util-linux uses the
    // new mount API on this RK3588 kernel because legacy bind-remount can be rejected.
    if let Err(new_api_error) = mount_path_read_only(&rootfs_c) {
        if unsafe {
            libc::mount(
                ptr::null(),
                rootfs_c.as_ptr(),
                ptr::null(),
                (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                ptr::null(),
            )
        } != 0 {
            bail!("make agent rootfs read-only failed: mount_setattr={new_api_error}; legacy={}", std::io::Error::last_os_error());
        }
    }

    let proc_source = CString::new("proc")?;
    let proc_target = CString::new(rootfs.join("proc").as_os_str().as_bytes())?;
    let proc_type = CString::new("proc")?;
    if unsafe {
        libc::mount(
            proc_source.as_ptr(),
            proc_target.as_ptr(),
            proc_type.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            ptr::null(),
        )
    } != 0 {
        bail!("mount agent procfs failed: {}", std::io::Error::last_os_error());
    }

    for source in &spec.container_read_only {
        bind_into_container(rootfs, source, true)?;
    }
    for source in &spec.read_write {
        bind_into_container(rootfs, source, false)?;
    }
    // Layer task-local Git metadata read-only over the writable workspace. This lets
    // agents use status/diff/log/show while preventing commit/reset/rebase from
    // changing the synthetic repository we prepared for them.
    for source in &spec.nested_read_only {
        bind_into_container(rootfs, source, true)?;
    }
    // Helper-only scratch for constructing the inner tmpfs root. It is deliberately
    // not part of spec.read_write, so the final Pi sandbox does not expose it.
    bind_into_container(rootfs, &spec.namespace_root_base, false)?;

    if unsafe { libc::chroot(rootfs_c.as_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let security = status.lines()
            .filter(|line| line.starts_with("CapEff:") || line.starts_with("CapBnd:") || line.starts_with("NoNewPrivs:") || line.starts_with("Seccomp:"))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("chroot agent container failed: {error}; euid={}; {security}", unsafe { libc::geteuid() });
    }
    std::env::set_current_dir("/").context("chdir inside agent container")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_path_read_only(path: &std::ffi::CString) -> anyhow::Result<()> {
    let attr = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NOSUID,
        attr_clr: libc::MOUNT_ATTR__ATIME,
        propagation: 0,
        userns_fd: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path.as_ptr(),
            0_u32,
            &attr as *const libc::mount_attr,
            std::mem::size_of::<libc::mount_attr>(),
        )
    };
    if result != 0 {
        bail!("mount_setattr read-only failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_container_mountpoint(rootfs: &Path, source: &Path) -> anyhow::Result<()> {
    use std::fs;
    let metadata = fs::metadata(source).with_context(|| format!("stat container bind {}", source.display()))?;
    let relative = source.strip_prefix("/").with_context(|| format!("container bind must be absolute: {}", source.display()))?;
    let destination = rootfs.join(relative);
    if metadata.is_dir() {
        fs::create_dir_all(&destination)?;
    } else {
        if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
        if !destination.exists() { fs::File::create(&destination)?; }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_into_container(rootfs: &Path, source: &Path, read_only: bool) -> anyhow::Result<()> {
    use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, ptr};

    let metadata = fs::metadata(source).with_context(|| format!("stat container bind {}", source.display()))?;
    let relative = source.strip_prefix("/").with_context(|| format!("container bind must be absolute: {}", source.display()))?;
    let destination = rootfs.join(relative);
    let source_c = CString::new(source.as_os_str().as_bytes())?;
    let destination_c = CString::new(destination.as_os_str().as_bytes())?;
    let flags = if metadata.is_dir() { libc::MS_BIND | libc::MS_REC } else { libc::MS_BIND };
    if unsafe { libc::mount(source_c.as_ptr(), destination_c.as_ptr(), ptr::null(), flags as libc::c_ulong, ptr::null()) } != 0 {
        bail!("bind container path {} failed: {}", source.display(), std::io::Error::last_os_error());
    }
    if read_only {
        if unsafe {
            libc::mount(
                ptr::null(),
                destination_c.as_ptr(),
                ptr::null(),
                (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                ptr::null(),
            )
        } != 0 {
            bail!("remount container path {} read-only failed: {}", source.display(), std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enter_agent_container(_spec: &SandboxSpec) -> anyhow::Result<()> {
    bail!("agent container requires Linux")
}

#[cfg(target_os = "linux")]
fn enable_agent_no_new_privs() -> anyhow::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!("set agent no_new_privs failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_agent_no_new_privs() -> anyhow::Result<()> { Ok(()) }

#[cfg(target_os = "linux")]
fn enter_sandbox_uid(uid: u32) -> anyhow::Result<()> {
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_DAC_OVERRIDE_BIT: u32 = 1 << 1;

    if unsafe { libc::geteuid() } != 0 {
        bail!("trusted sandbox uid isolation requires uid 0 launcher");
    }
    if !(SANDBOX_UID_MIN..=SANDBOX_UID_MAX).contains(&uid) {
        bail!("sandbox uid {uid} is outside reserved range");
    }

    // Keep only enough privilege to use the existing Landlock-approved
    // writable paths after switching away from uid 0. CAP_KILL is deliberately
    // not retained: Linux uid checks are the process-isolation boundary.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
        bail!("enable keepcaps for sandbox uid switch failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        bail!("clear sandbox supplementary groups failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::setresgid(uid, uid, uid) } != 0 {
        bail!("set sandbox gid {uid} failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        bail!("set sandbox uid {uid} failed: {}", std::io::Error::last_os_error());
    }

    let mut header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [
        CapData {
            effective: CAP_DAC_OVERRIDE_BIT,
            permitted: CAP_DAC_OVERRIDE_BIT,
            inheritable: CAP_DAC_OVERRIDE_BIT,
        },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) } != 0 {
        bail!("retain sandbox CAP_DAC_OVERRIDE failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0 {
        bail!("disable keepcaps after sandbox uid switch failed: {}", std::io::Error::last_os_error());
    }
    // Preserve only DAC override across exec so the isolated uid can use the
    // already-Landlock-confined shared caches/config and its workspace. No
    // CAP_KILL, CAP_SYS_ADMIN, CAP_SETUID, or CAP_SETGID survives into the agent.
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, 1, 0, 0) } != 0 {
        bail!("raise sandbox ambient CAP_DAC_OVERRIDE failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enter_sandbox_uid(_uid: u32) -> anyhow::Result<()> {
    bail!("sandbox uid isolation requires Linux")
}

#[cfg(target_os = "linux")]
fn drop_agent_capabilities() -> anyhow::Result<()> {
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) } != 0 {
        bail!("drop agent process capabilities failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            bail!("clear agent ambient capabilities failed: {error}");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_agent_capabilities() -> anyhow::Result<()> { Ok(()) }

#[cfg(target_os = "linux")]
fn apply_policy(spec: &SandboxSpec, signals_are_uid_isolated: bool) -> anyhow::Result<()> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // Prefer Landlock when the kernel can fully enforce our fixed ABI V3 policy.  Some
    // vendor kernels expose no Landlock at all; those fall back to a rootless user+mount
    // namespace containing only the same explicit path allowlist.
    let abi = ABI::V3;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(&spec.read_only, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&spec.read_write, AccessFs::from_all(abi)))?
        .set_compatibility(CompatLevel::HardRequirement)
        .restrict_self()
        .context("apply Landlock filesystem policy")?;

    match status.ruleset {
        RulesetStatus::FullyEnforced if status.no_new_privs => {}
        RulesetStatus::NotEnforced => apply_namespace_fs_policy(spec)
            .context("Landlock unavailable and rootless namespace fallback failed")?,
        _ => bail!("Landlock policy was only partially enforced; refusing ambiguous sandbox: {status:?}"),
    }

    install_seccomp_denylist(signals_are_uid_isolated)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_namespace_fs_policy(spec: &SandboxSpec) -> anyhow::Result<()> {
    use std::{
        ffi::CString,
        fs,
        os::unix::ffi::OsStrExt,
        ptr,
    };

    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let root = spec.namespace_root_base.join(format!("{}", unsafe { libc::getpid() }));
    if root.exists() {
        fs::remove_dir_all(&root).with_context(|| format!("clear namespace root {}", root.display()))?;
    }
    fs::create_dir_all(&root).with_context(|| format!("create namespace root {}", root.display()))?;

    // Some vendor kernels reject creating user+mount namespaces in one unshare(2)
    // call even though util-linux `unshare --user --map-root-user --mount` works. Match
    // that safe ordering explicitly. When the worker itself already runs as uid 0 inside
    // a rootless user namespace (for example our Ubuntu container smoke), creating a
    // nested user namespace may be forbidden. In that case reuse the existing rootless
    // user namespace and create only a fresh mount namespace for the agent.
    let created_user_namespace = if spec.container_rootfs.is_some() {
        // The outer agent container already mapped host worker uid/gid to namespace root.
        // Reuse it instead of depending on nested user namespaces or /proc inside the container.
        false
    } else if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
        true
    } else {
        let error = std::io::Error::last_os_error();
        if root_in_noninitial_user_namespace()? {
            false
        } else {
            bail!("unshare user namespace failed: {error}");
        }
    };

    if created_user_namespace {
        // Map namespace uid/gid 0 to the unprivileged host worker user. This gives enough
        // capability inside the new namespace to construct mounts, but no host-root identity.
        let map_gid = prepare_gid_mapping("user namespace")?;
        fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).context("write user namespace uid_map")?;
        if map_gid {
            fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).context("write user namespace gid_map")?;
            if unsafe { libc::setresgid(0, 0, 0) } != 0 {
                bail!("setresgid inside user namespace failed: {}", std::io::Error::last_os_error());
            }
        }
        if unsafe { libc::setresuid(0, 0, 0) } != 0 {
            bail!("setresuid inside user namespace failed: {}", std::io::Error::last_os_error());
        }
    }

    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        bail!("unshare mount namespace failed: {}", std::io::Error::last_os_error());
    }

    let slash = CString::new("/")?;
    if unsafe {
        libc::mount(
            ptr::null(),
            slash.as_ptr(),
            ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            ptr::null(),
        )
    } != 0
    {
        bail!("make mount namespace private failed: {}", std::io::Error::last_os_error());
    }

    let root_c = c_path(&root)?;
    let tmpfs = CString::new("tmpfs")?;
    let data = CString::new("mode=0755,size=64m")?;
    if unsafe {
        libc::mount(
            tmpfs.as_ptr(),
            root_c.as_ptr(),
            tmpfs.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            data.as_ptr().cast(),
        )
    } != 0
    {
        bail!("mount sandbox tmpfs root failed: {}", std::io::Error::last_os_error());
    }

    for source in &spec.read_only {
        bind_into_root(&root, source, true)?;
    }
    for source in &spec.read_write {
        bind_into_root(&root, source, false)?;
    }
    mirror_root_symlinks(&root)?;

    let old_root = root.join(".oldroot");
    fs::create_dir_all(&old_root)?;
    std::env::set_current_dir(&root).context("chdir to namespace root")?;
    let dot = CString::new(".")?;
    let old = CString::new(".oldroot")?;
    if unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr()) } != 0 {
        bail!("pivot_root failed: {}", std::io::Error::last_os_error());
    }
    std::env::set_current_dir("/").context("chdir after pivot_root")?;
    let old_abs = CString::new("/.oldroot")?;
    if unsafe { libc::umount2(old_abs.as_ptr(), libc::MNT_DETACH) } != 0 {
        bail!("detach old root failed: {}", std::io::Error::last_os_error());
    }
    fs::remove_dir("/.oldroot").context("remove detached old root mountpoint")?;
    std::env::set_current_dir(&spec.working_dir)
        .with_context(|| format!("enter sandbox workspace {}", spec.working_dir.display()))?;
    return Ok(());

    fn root_in_noninitial_user_namespace() -> anyhow::Result<bool> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(false);
        }
        let uid_map = fs::read_to_string("/proc/self/uid_map").context("read current user namespace uid_map")?;
        let mut fields = uid_map
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let inside = fields.next().and_then(|value| value.parse::<u64>().ok());
        let outside = fields.next().and_then(|value| value.parse::<u64>().ok());
        let length = fields.next().and_then(|value| value.parse::<u64>().ok());
        Ok(matches!((inside, outside, length), (Some(0), Some(host), Some(span)) if host != 0 || span != u32::MAX as u64))
    }

    fn mirror_root_symlinks(root: &Path) -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        for name in ["bin", "sbin", "lib", "lib64"] {
            let host = Path::new("/").join(name);
            let metadata = match fs::symlink_metadata(&host) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).with_context(|| format!("stat root alias {}", host.display())),
            };
            if !metadata.file_type().is_symlink() { continue; }
            let target = fs::read_link(&host).with_context(|| format!("read root alias {}", host.display()))?;
            let destination = root.join(name);
            if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
                fs::remove_file(&destination).with_context(|| format!("replace root alias {}", destination.display()))?;
            }
            symlink(&target, &destination)
                .with_context(|| format!("mirror root alias {} -> {}", destination.display(), target.display()))?;
        }
        Ok(())
    }

    fn c_path(path: &Path) -> anyhow::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).context("sandbox path contains NUL")
    }

    fn bind_into_root(root: &Path, source: &Path, read_only: bool) -> anyhow::Result<()> {
        let metadata = fs::metadata(source).with_context(|| format!("stat sandbox path {}", source.display()))?;
        let relative = source.strip_prefix("/").with_context(|| format!("sandbox path must be absolute: {}", source.display()))?;
        let destination = root.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(&destination)?;
        } else {
            if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
            if !destination.exists() { fs::File::create(&destination)?; }
        }
        let source_c = c_path(source)?;
        let destination_c = c_path(&destination)?;
        let bind_flags = if metadata.is_dir() { libc::MS_BIND | libc::MS_REC } else { libc::MS_BIND };
        if unsafe {
            libc::mount(
                source_c.as_ptr(),
                destination_c.as_ptr(),
                std::ptr::null(),
                bind_flags as libc::c_ulong,
                std::ptr::null(),
            )
        } != 0
        {
            bail!(
                "bind mount {} -> {} failed: {}",
                source.display(),
                destination.display(),
                std::io::Error::last_os_error()
            );
        }
        if read_only && metadata.is_dir() {
            let remount_read_only = unsafe {
                libc::mount(
                    std::ptr::null(),
                    destination_c.as_ptr(),
                    std::ptr::null(),
                    (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                    std::ptr::null(),
                )
            } == 0;
            if !remount_read_only {
                // Nested rootless mount namespaces on some vendor kernels reject a
                // second bind-remount. Accept that only when the source is already
                // non-writable because the outer Ubuntu image mount is read-only.
                let writable = unsafe { libc::access(source_c.as_ptr(), libc::W_OK) } == 0;
                if writable {
                    bail!("read-only sandbox directory is writable by the worker: {}", source.display());
                }
            }
        } else if read_only {
            // Prefer an actual read-only bind remount. Some vendor kernels reject this for
            // individual files, so retain the permission-based fallback used by the host
            // worker. The fallback is only accepted when the source inode is already
            // non-writable to the worker; otherwise fail closed.
            let remount_read_only = unsafe {
                libc::mount(
                    std::ptr::null(),
                    destination_c.as_ptr(),
                    std::ptr::null(),
                    (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                    std::ptr::null(),
                )
            } == 0;
            if !remount_read_only {
                let writable = unsafe { libc::access(source_c.as_ptr(), libc::W_OK) } == 0;
                if writable {
                    bail!("read-only sandbox file is writable by the worker: {}", source.display());
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn install_seccomp_denylist(signals_are_uid_isolated: bool) -> anyhow::Result<()> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
        SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::{collections::BTreeMap, convert::TryInto};

    let mut denied = vec![
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
    ];
    if !signals_are_uid_isolated {
        denied.extend([
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_rt_sigqueueinfo,
            libc::SYS_rt_tgsigqueueinfo,
            libc::SYS_pidfd_send_signal,
        ]);
    }
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        denied.into_iter().map(|syscall| (syscall, vec![])).collect();

    if !signals_are_uid_isolated {
        // Bun/JSC uses tgkill(tgid=self, tid=worker, SIGPWR) to suspend its own
        // threads even for trivial commands such as `opencode --version`.
        // Without per-sandbox uid isolation, keep cross-process signalling
        // blocked while allowing only the sandbox root thread group.
        let sandbox_tgid = unsafe { libc::getpid() } as u64;
        rules.insert(
            libc::SYS_tgkill,
            vec![SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                sandbox_tgid,
            )?])?],
        );
    }

    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| anyhow::anyhow!("unsupported seccomp architecture {}", std::env::consts::ARCH))?,
    )?
    .try_into()?;
    apply_filter(&filter).context("install seccomp filter")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_policy(_spec: &SandboxSpec, _signals_are_uid_isolated: bool) -> anyhow::Result<()> {
    bail!("embedded agent sandbox requires Linux; refusing to run an unsandboxed agent")
}

pub async fn prepare_agent_workspace(source: &Path, destination: &Path, base_ref: Option<&str>) -> anyhow::Result<()> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    let base_ref = base_ref.map(str::to_string);
    tokio::task::spawn_blocking(move || prepare_agent_workspace_blocking(&source, &destination, base_ref.as_deref())).await??;
    Ok(())
}

fn prepare_agent_workspace_blocking(source: &Path, destination: &Path, base_ref: Option<&str>) -> anyhow::Result<()> {
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;

    if let Some(base_ref) = base_ref {
        extract_git_tree(source, destination, base_ref)?;
    } else {
        copy_tree(source, destination, true)?;
    }
    init_sandbox_git(destination, "lazyteam-base", "LazyTeam base snapshot")?;

    if base_ref.is_some() {
        clear_worktree_except_git(destination)?;
        copy_tree(source, destination, true)?;
        sandbox_git_ok(destination, &["add", "-A"])?;
        let changed = std::process::Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null", "diff", "--cached", "--quiet"])
            .current_dir(destination)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()?;
        sandbox_git_ok(destination, &["checkout", "-b", "lazyteam-task"])?;
        if !changed.success() {
            sandbox_git_ok(destination, &["commit", "-m", "LazyTeam task snapshot"])?;
        }
    } else {
        sandbox_git_ok(destination, &["branch", "-M", "lazyteam-task"])?;
    }
    sanitize_sandbox_git(destination)?;
    Ok(())
}

fn extract_git_tree(source: &Path, destination: &Path, revision: &str) -> anyhow::Result<()> {
    let mut archive = std::process::Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "archive", "--format=tar", revision])
        .current_dir(source)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("archive sandbox base {revision}"))?;
    let stdout = archive.stdout.take().context("capture git archive stdout")?;
    let output = std::process::Command::new("tar")
        .args(["-xf", "-", "-C"])
        .arg(destination)
        .stdin(stdout)
        .output()
        .context("extract sandbox base archive")?;
    let archive_output = archive.wait_with_output().context("wait for sandbox git archive")?;
    if !archive_output.status.success() {
        bail!("git archive {revision} failed: {}", String::from_utf8_lossy(&archive_output.stderr));
    }
    if !output.status.success() {
        bail!("extract sandbox base archive failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn init_sandbox_git(destination: &Path, branch: &str, message: &str) -> anyhow::Result<()> {
    sandbox_git_ok(destination, &["init", "-q"])?;
    sandbox_git_ok(destination, &["config", "--local", "user.name", "LazyTeam Sandbox"])?;
    sandbox_git_ok(destination, &["config", "--local", "user.email", "sandbox@lazyteam.local"])?;
    sandbox_git_ok(destination, &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")])?;
    sandbox_git_ok(destination, &["add", "-A"])?;
    sandbox_git_ok(destination, &["commit", "-q", "-m", message])?;
    Ok(())
}

fn sanitize_sandbox_git(destination: &Path) -> anyhow::Result<()> {
    let git_dir = destination.join(".git");
    let hooks = git_dir.join("hooks");
    if hooks.exists() { std::fs::remove_dir_all(&hooks)?; }
    std::fs::create_dir_all(&hooks)?;
    for args in [
        ["config", "--local", "core.hooksPath", "/dev/null"].as_slice(),
        ["config", "--local", "credential.helper", ""].as_slice(),
        ["config", "--local", "core.fsmonitor", "false"].as_slice(),
        ["config", "--local", "protocol.allow", "never"].as_slice(),
        ["config", "--local", "protocol.file.allow", "never"].as_slice(),
    ] {
        sandbox_git_ok(destination, args)?;
    }
    let remotes = sandbox_git_output(destination, &["remote"])?;
    for remote in remotes.lines().filter(|line| !line.trim().is_empty()) {
        sandbox_git_ok(destination, &["remote", "remove", remote.trim()])?;
    }
    Ok(())
}

fn sandbox_git_ok(path: &Path, args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    if !output.status.success() {
        bail!("sandbox git {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn sandbox_git_output(path: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    if !output.status.success() {
        bail!("sandbox git {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn clear_worktree_except_git(path: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name() == OsStr::new(".git") { continue; }
        remove_path(&entry.path())?;
    }
    Ok(())
}

pub async fn sync_agent_workspace(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    tokio::task::spawn_blocking(move || {
        for entry in std::fs::read_dir(&destination)? {
            let entry = entry?;
            if entry.file_name() == OsStr::new(".git") {
                continue;
            }
            remove_path(&entry.path())?;
        }
        copy_tree(&source, &destination, true)
    })
    .await??;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path, skip_git: bool) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if (skip_git && name == OsStr::new(".git"))
            || LOCAL_ARTIFACT_DIRS.iter().any(|ignored| name == OsStr::new(ignored))
        {
            continue;
        }
        let source_path = entry.path();
        let dest_path = destination.join(&name);
        let metadata = std::fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            std::fs::set_permissions(&dest_path, metadata.permissions())?;
            copy_tree(&source_path, &dest_path, skip_git)?;
        } else if metadata.file_type().is_file() {
            std::fs::copy(&source_path, &dest_path)?;
            std::fs::set_permissions(&dest_path, metadata.permissions())?;
        } else if metadata.file_type().is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(std::fs::read_link(&source_path)?, &dest_path)?;
            #[cfg(not(unix))]
            bail!("symlinked task files require Unix");
        } else {
            bail!("refusing to mirror special file {}", source_path.display());
        }
    }
    Ok(())
}

fn remove_path(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn resolve_program(program: &str, path: &OsStr) -> Option<PathBuf> {
    let candidate = PathBuf::from(program);
    if candidate.components().count() > 1 {
        return candidate.exists().then_some(candidate);
    }
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn path_depth(path: &Path) -> usize { path.components().count() }

fn common_ancestor(a: &Path, b: &Path) -> Option<PathBuf> {
    let mut common = PathBuf::new();
    for (a, b) in a.components().zip(b.components()) {
        if a != b { break; }
        common.push(a.as_os_str());
    }
    (!common.as_os_str().is_empty()).then_some(common)
}

fn canonical_dir(path: &Path) -> anyhow::Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

#[cfg(unix)]
async fn set_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_dir(_path: &Path) -> anyhow::Result<()> { Ok(()) }

#[cfg(unix)]
async fn set_traversable_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o711)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_traversable_private_dir(_path: &Path) -> anyhow::Result<()> { Ok(()) }

#[cfg(unix)]
async fn set_private_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_file(_path: &Path) -> anyhow::Result<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_allows_self_tgkill_but_blocks_parent_tgkill() {
        unsafe {
            let child = libc::fork();
            assert!(child >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if child == 0 {
                let parent = libc::getppid();
                if install_seccomp_denylist(false).is_err() {
                    libc::_exit(10);
                }
                let own_pid = libc::getpid();
                let own_tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;
                if libc::syscall(libc::SYS_tgkill, own_pid, own_tid, 0) != 0 {
                    libc::_exit(11);
                }
                if libc::syscall(libc::SYS_tgkill, parent, parent, 0) == 0 {
                    libc::_exit(12);
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                    libc::_exit(13);
                }
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert_eq!(status, 0, "seccomp tgkill probe child status={status}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_uid_isolation_mode_allows_child_termination() {
        unsafe {
            let child = libc::fork();
            assert!(child >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if child == 0 {
                if install_seccomp_denylist(true).is_err() {
                    libc::_exit(20);
                }
                let grandchild = libc::fork();
                if grandchild < 0 {
                    libc::_exit(21);
                }
                if grandchild == 0 {
                    libc::pause();
                    libc::_exit(0);
                }
                if libc::kill(grandchild, libc::SIGKILL) != 0 {
                    libc::_exit(22);
                }
                let mut status = 0;
                if libc::waitpid(grandchild, &mut status, 0) != grandchild {
                    libc::_exit(23);
                }
                if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
                    libc::_exit(24);
                }
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert_eq!(status, 0, "uid-isolated signal seccomp child status={status}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_uid_allocator_is_stable_and_unique_per_workspace() {
        let root = std::env::temp_dir().join(format!("lazyteam-sandbox-uids-{}", uuid::Uuid::new_v4()));
        let uid_dir = root.join("uids");
        let a = root.join("agent-workspaces").join(uuid::Uuid::new_v4().to_string());
        let b = root.join("agent-workspaces").join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::create_dir_all(&uid_dir).unwrap();

        let uid_a = sandbox_uid_for_workspace(&uid_dir, &a).unwrap();
        let uid_a_again = sandbox_uid_for_workspace(&uid_dir, &a).unwrap();
        let uid_b = sandbox_uid_for_workspace(&uid_dir, &b).unwrap();
        assert_eq!(uid_a, uid_a_again);
        assert_ne!(uid_a, uid_b);
        assert!((SANDBOX_UID_MIN..=SANDBOX_UID_MAX).contains(&uid_a));
        assert!((SANDBOX_UID_MIN..=SANDBOX_UID_MAX).contains(&uid_b));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pi_config_dir_allows_traversal_but_not_listing() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("lazyteam-pi-config-mode-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        set_traversable_private_dir(&root).await.unwrap();
        let mode = tokio::fs::metadata(&root).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o711);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn runtime_metadata_allowlist_is_narrow() {
        let mut read_only = BTreeSet::new();
        let mut container_read_only = BTreeSet::new();
        add_runtime_metadata_read_only(&mut read_only, &mut container_read_only, None);

        for path in RUNTIME_PROC_READ_ONLY {
            assert!(read_only.contains(Path::new(path)), "missing {path}");
        }
        assert!(!read_only.contains(Path::new("/proc")));
        assert!(!read_only.contains(Path::new("/sys")));
        assert!(container_read_only.is_empty());
    }

    #[test]
    fn managed_rust_paths_require_image_toolchain_and_parse_versions() {
        let root = std::env::temp_dir().join(format!(
            "lazyteam-managed-rust-paths-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(root.join("opt/lazyteam/rustup")).unwrap();
        std::fs::create_dir_all(root.join("opt/lazyteam/cargo/bin")).unwrap();
        std::fs::write(root.join("opt/lazyteam/cargo/bin/cargo"), b"proxy").unwrap();

        let (rustup_home, cargo_bin) = container_managed_rust_paths(Some(&root)).unwrap();
        assert_eq!(rustup_home, PathBuf::from("/opt/lazyteam/rustup"));
        assert_eq!(cargo_bin, PathBuf::from("/opt/lazyteam/cargo/bin"));

        let (host_rustup, host_cargo_bin) = host_visible_managed_rust_paths(Some(&root)).unwrap();
        assert_eq!(host_rustup, root.join("opt/lazyteam/rustup"));
        assert_eq!(host_cargo_bin, root.join("opt/lazyteam/cargo/bin"));
        assert_eq!(managed_rust_version("rustc 1.85.0 (hash 2025-01-01)"), Some((1, 85, 0)));
        assert_eq!(managed_rust_version("cargo 1.90.1 (hash 2025-01-01)"), Some((1, 90, 1)));

        std::fs::remove_file(root.join("opt/lazyteam/cargo/bin/cargo")).unwrap();
        assert!(container_managed_rust_paths(Some(&root)).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn container_native_paths_join_the_canonical_read_only_policy() {
        let root = std::env::temp_dir().join(format!(
            "lazyteam-container-native-policy-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(root.join("opt/lazyteam")).unwrap();

        let mut read_only = BTreeSet::new();
        add_container_native_read_only(&mut read_only, Some(&root));
        assert_eq!(
            read_only.into_iter().collect::<Vec<_>>(),
            vec![PathBuf::from("/opt/lazyteam")]
        );

        let mut absent = BTreeSet::new();
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        add_container_native_read_only(&mut absent, Some(&empty));
        assert!(absent.is_empty());

        let mut host_mode = BTreeSet::new();
        add_container_native_read_only(&mut host_mode, None);
        assert!(host_mode.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn common_ancestor_finds_runtime_root() {
        let root = common_ancestor(
            Path::new("/opt/pi/bin/pi"),
            Path::new("/opt/pi/lib/node_modules/pi/cli.js"),
        ).unwrap();
        assert_eq!(root, PathBuf::from("/opt/pi"));
    }

    #[tokio::test]
    async fn agent_workspace_mirror_has_sanitized_git_and_omits_local_build_artifacts() {
        let root = std::env::temp_dir().join(format!("lazyteam-sandbox-test-{}", uuid::Uuid::new_v4()));
        let source = root.join("source");
        let dest = root.join("dest");
        tokio::fs::create_dir_all(source.join("target")).await.unwrap();
        tokio::fs::create_dir_all(source.join("src")).await.unwrap();
        tokio::fs::write(source.join("target").join("artifact"), b"artifact").await.unwrap();
        tokio::fs::write(source.join("src").join("lib.rs"), b"pub fn ok() {}\n").await.unwrap();

        std::process::Command::new("git").args(["init", "-q"]).current_dir(&source).status().unwrap();
        std::process::Command::new("git").args(["remote", "add", "origin", "https://user:secret@example.invalid/repo.git"]).current_dir(&source).status().unwrap();
        std::process::Command::new("git").args(["config", "credential.helper", "store"]).current_dir(&source).status().unwrap();
        std::process::Command::new("git").args(["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "add", "src/lib.rs"]).current_dir(&source).status().unwrap();
        std::process::Command::new("git").args(["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base"]).current_dir(&source).status().unwrap();
        let base = String::from_utf8(std::process::Command::new("git").args(["rev-parse", "HEAD"]).current_dir(&source).output().unwrap().stdout).unwrap();
        tokio::fs::write(source.join("src").join("lib.rs"), b"pub fn changed() {}\n").await.unwrap();
        tokio::fs::write(source.join("new.txt"), b"task change\n").await.unwrap();

        prepare_agent_workspace(&source, &dest, Some(base.trim())).await.unwrap();
        assert!(dest.join("src").join("lib.rs").is_file());
        assert!(dest.join(".git").is_dir());
        assert!(!dest.join("target").exists());
        let changed = sandbox_git_output(&dest, &["diff", "--name-only", "lazyteam-base..HEAD"]).unwrap();
        assert!(changed.lines().any(|line| line == "src/lib.rs"));
        assert!(changed.lines().any(|line| line == "new.txt"));
        assert_eq!(sandbox_git_output(&dest, &["remote"]).unwrap(), "");
        assert_eq!(sandbox_git_output(&dest, &["config", "--local", "core.hooksPath"]).unwrap(), "/dev/null");
        assert_eq!(sandbox_git_output(&dest, &["config", "--local", "credential.helper"]).unwrap(), "");
        assert!(!tokio::fs::read_to_string(dest.join(".git").join("config")).await.unwrap().contains("example.invalid"));
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn sync_never_copies_agent_git_metadata() {
        let root = std::env::temp_dir().join(format!("lazyteam-sandbox-sync-test-{}", uuid::Uuid::new_v4()));
        let agent = root.join("agent");
        let trusted = root.join("trusted");
        tokio::fs::create_dir_all(agent.join(".git")).await.unwrap();
        tokio::fs::create_dir_all(trusted.join(".git")).await.unwrap();
        tokio::fs::write(agent.join(".git").join("config"), b"attacker\n").await.unwrap();
        tokio::fs::write(trusted.join(".git").join("config"), b"trusted\n").await.unwrap();
        tokio::fs::write(agent.join("changed.txt"), b"changed\n").await.unwrap();

        sync_agent_workspace(&agent, &trusted).await.unwrap();
        assert_eq!(tokio::fs::read(trusted.join(".git").join("config")).await.unwrap(), b"trusted\n");
        assert_eq!(tokio::fs::read(trusted.join("changed.txt")).await.unwrap(), b"changed\n");
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
