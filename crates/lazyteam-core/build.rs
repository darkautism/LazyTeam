use std::{env, path::PathBuf, process::Command};

fn git_output(args: &[&str], manifest_dir: &PathBuf) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=LAZYTEAM_GIT_SHA");
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"], &manifest_dir) {
        println!("cargo:rerun-if-changed=../../.git/{reference}");
    } else {
        println!("cargo:rerun-if-changed=../../.git/HEAD");
    }

    let sha = env::var("LAZYTEAM_GIT_SHA")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| git_output(&["rev-parse", "HEAD"], &manifest_dir))
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=LAZYTEAM_BUILD_GIT_SHA={sha}");
}
