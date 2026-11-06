//! `wirelab censor build`: the censor for the wire container, with nDPI
//! linked in, built inside Docker so the host needs neither Go nor a C
//! toolchain. See containers/censor-build/Dockerfile.

use crate::docker::Docker;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub const IMAGE: &str = "wl-censor-build";
/// Written next to the binary: the nDPI commit it was linked against.
pub const NDPI_STAMP: &str = "containers/wire/bin/wl-censor.ndpi-commit";

pub fn build(docker: &Docker, root: &Path) -> Result<String> {
    let ctx = docker.daemon_path(&root.join("wirelab-censor"))?;
    let file = docker.daemon_path(&root.join("containers/censor-build/Dockerfile"))?;
    // --network host: inside WSL's mirrored networking the default bridge
    // cannot reach a resolver, and the build clones nDPI.
    docker.run_visible(&["build", "--network", "host", "-t", IMAGE, "-f", &file, &ctx])?;

    // The image is FROM scratch holding the files; a stopped container is
    // enough to copy them out, and needs no BuildKit.
    let id = docker.run(&["create", IMAGE, "/wl-censor"])?.trim().to_string();
    let bin = root.join("containers/wire/bin");
    fs::create_dir_all(&bin)?;
    let dest = docker.daemon_path(&bin)?;
    let copied = ["wl-censor", "wl-censor.ndpi-commit"]
        .iter()
        .try_for_each(|f| docker.run(&["cp", &format!("{id}:/{f}"), &format!("{dest}/{f}")]).map(|_| ()));
    let _ = docker.run(&["rm", &id]);
    copied.context("copying the censor out of the build image")?;
    let commit = fs::read_to_string(root.join(NDPI_STAMP)).unwrap_or_default();
    Ok(commit.trim().to_string())
}
