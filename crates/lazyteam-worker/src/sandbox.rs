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
const SPEC_ENV: &str = "LAZYTEAM_SANDBOX_SPEC";
const LOCAL_ARTIFACT_DIRS: &[&str] = &["target", "node_modules", "__pycache__", ".pytest_cache", ".venv"];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxSpec {
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    working_dir: PathBuf,
    namespace_root_base: PathBuf,
    container_rootfs: Option<PathBuf>,
    container_read_only: Vec<PathBuf>,
    #[serde(default)]
    trusted_container_daemon: bool,
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
}

impl AgentSandbox {
    pub async fn prepare(state_dir: &Path, pi_bin: &str, container_rootfs: Option<&Path>) -> anyhow::Result<Self> {
        let state_dir = canonical_dir(state_dir).context("canonicalize worker state directory")?;
        let container_rootfs = container_rootfs.map(canonical_dir).transpose().context("canonicalize agent rootfs")?;
        let trusted_container_daemon = container_rootfs.is_some()
            && std::env::var_os("LAZYTEAM_TRUSTED_CONTAINER_DAEMON").is_some_and(|value| value == "1");
        if trusted_container_daemon && unsafe { libc::geteuid() } != 0 {
            bail!("trusted container daemon mode requires container uid 0");
        }
        let pi_config_dir = state_dir.join("pi-agent");
        let home_dir = state_dir.join("agent-home");
        let cargo_home = state_dir.join("agent-cache").join("cargo");
        let cargo_target_dir = state_dir.join("agent-cache").join("target");
        let tmp_dir = state_dir.join("agent-tmp");
        let probe_dir = state_dir.join("agent-probe");
        let namespace_root_base = state_dir.join("sandbox-roots");
        if namespace_root_base.exists() {
            tokio::fs::remove_dir_all(&namespace_root_base).await?;
        }
        for dir in [&pi_config_dir, &home_dir, &cargo_home, &cargo_target_dir, &tmp_dir, &probe_dir, &namespace_root_base] {
            tokio::fs::create_dir_all(dir).await?;
            set_private_dir(dir).await?;
        }
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

        if let Some(program) = resolve_program(pi_bin, &host_path) {
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

        let rustup_home = container_rootfs.is_none().then(|| std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
            .filter(|path| path.exists())
            .and_then(|path| std::fs::canonicalize(path).ok())).flatten();
        if let Some(path) = &rustup_home {
            read_only.insert(path.clone());
        }

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
        "ready: filesystem isolation (Landlock or rootless user/mount namespace) + seccomp denylist"
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

        let spec = SandboxSpec {
            read_only: self.read_only.clone(),
            read_write,
            working_dir: workspace.clone(),
            namespace_root_base: self.namespace_root_base.clone(),
            container_rootfs: self.container_rootfs.clone(),
            container_read_only: self.container_read_only.clone(),
            trusted_container_daemon: self.trusted_container_daemon,
        };
        let mut command = Command::new(std::env::current_exe().context("resolve lazyteam-worker executable")?);
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

        let mut command = self.command("/bin/sh", &self.probe_dir, None)?;
        command.arg("-c").arg("if kill -0 \"$PPID\" 2>/dev/null; then exit 91; else exit 0; fi");
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        let output = command.output().await.context("probe sandbox process isolation")?;
        if !output.status.success() {
            bail!("agent sandbox can signal its parent daemon; refusing to start");
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
    None
}

fn sandbox_exec(mut args: Vec<OsString>, enter_container: bool) -> anyhow::Result<()> {
    if args.is_empty() {
        bail!("sandbox helper missing program");
    }
    let program = args.remove(0);
    let raw = std::env::var(SPEC_ENV).context("sandbox helper missing policy")?;
    let spec: SandboxSpec = serde_json::from_str(&raw).context("parse sandbox policy")?;
    if enter_container {
        enter_agent_container(&spec)?;
    }
    enable_agent_no_new_privs()?;
    apply_policy(&spec)?;
    drop_agent_capabilities()?;

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(program);
        command.args(args).env_remove(SPEC_ENV);
        let error = command.exec();
        Err(error).context("exec sandboxed agent")
    }
    #[cfg(not(unix))]
    {
        let _ = (program, args);
        bail!("embedded agent sandbox is only supported on Unix")
    }
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
    for source in spec.container_read_only.iter().chain(spec.read_write.iter()).chain(std::iter::once(&spec.namespace_root_base)) {
        prepare_container_mountpoint(rootfs, source)?;
    }

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

    for source in &spec.container_read_only {
        bind_into_container(rootfs, source, true)?;
    }
    for source in &spec.read_write {
        bind_into_container(rootfs, source, false)?;
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
fn apply_policy(spec: &SandboxSpec) -> anyhow::Result<()> {
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

    install_seccomp_denylist()?;
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
fn install_seccomp_denylist() -> anyhow::Result<()> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::{collections::BTreeMap, convert::TryInto};

    let denied = [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_send_signal,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
    ];
    let rules: BTreeMap<i64, Vec<SeccompRule>> =
        denied.into_iter().map(|syscall| (syscall, vec![])).collect();
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
fn apply_policy(_spec: &SandboxSpec) -> anyhow::Result<()> {
    bail!("embedded agent sandbox requires Linux; refusing to run an unsandboxed agent")
}

pub async fn prepare_agent_workspace(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    tokio::task::spawn_blocking(move || {
        if destination.exists() {
            std::fs::remove_dir_all(&destination)?;
        }
        std::fs::create_dir_all(&destination)?;
        copy_tree(&source, &destination, true)
    })
    .await??;
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
            copy_tree(&source_path, &dest_path, false)?;
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

    #[test]
    fn common_ancestor_finds_runtime_root() {
        let root = common_ancestor(
            Path::new("/opt/pi/bin/pi"),
            Path::new("/opt/pi/lib/node_modules/pi/cli.js"),
        ).unwrap();
        assert_eq!(root, PathBuf::from("/opt/pi"));
    }

    #[tokio::test]
    async fn agent_workspace_mirror_omits_git_and_local_build_artifacts() {
        let root = std::env::temp_dir().join(format!("lazyteam-sandbox-test-{}", uuid::Uuid::new_v4()));
        let source = root.join("source");
        let dest = root.join("dest");
        tokio::fs::create_dir_all(source.join(".git")).await.unwrap();
        tokio::fs::create_dir_all(source.join("target")).await.unwrap();
        tokio::fs::create_dir_all(source.join("src")).await.unwrap();
        tokio::fs::write(source.join(".git").join("config"), b"secret git metadata").await.unwrap();
        tokio::fs::write(source.join("target").join("artifact"), b"artifact").await.unwrap();
        tokio::fs::write(source.join("src").join("lib.rs"), b"pub fn ok() {}\n").await.unwrap();

        prepare_agent_workspace(&source, &dest).await.unwrap();
        assert!(dest.join("src").join("lib.rs").is_file());
        assert!(!dest.join(".git").exists());
        assert!(!dest.join("target").exists());
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
