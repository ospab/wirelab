# Getting started

[Русский](../ru/getting-started.md) · [Docs](../README.md)

## What you need

| | |
|---|---|
| Docker Engine with the Compose plugin | On Linux, natively. On Windows, inside a WSL2 distro: wirelab calls `wsl -d <distro> -e docker`. The distro is `Debian` unless `WIRELAB_WSL_DISTRO` names another. |
| Rust, stable | Builds the `wirelab` command. On Windows either the MSVC or the GNU toolchain (`stable-x86_64-pc-windows-gnu`) works; the project needs no C compiler. |
| git | Cargo fetches the OSTP protocol core from github.com/ospab/ostp for the simulator. |
| curl | Recipes download protocol releases. Windows 10 and later ship it. |
| Free disk space | A few GB where Docker keeps its data (on Windows: the drive holding the WSL distro's disk) and where the checkout lives (captures, downloads, runs). |

Go is not needed: the censor is built inside Docker.

## Build

```bash
git clone https://github.com/ospab/wirelab
cd wirelab
cargo build --release
```

The binary is `target/release/wirelab` (`wirelab.exe` on Windows). The examples below call it `wirelab`.

## Check the machine

```bash
wirelab doctor
```

It checks Docker and Compose, the WSL distro, netem, packet sockets and WireGuard in the kernel, free space where captures and Docker's data live, and whether the censor is built. Each problem comes with the command that fixes it; the exit code is 1 when something must be fixed first.

## Build the censor

```bash
wirelab censor build
```

This builds `wl-censor` with nDPI inside a container and copies it to `containers/wire/bin/`. Without it a lab still runs, but the wire forwards in the kernel and there is no censor. See [Censor](censor.md).

## First lab

```bash
wirelab lab up --recipe ostp --set transport=tls
wirelab lab panel
```

`lab up` builds the node and wire images on first use, starts the client, wire, server and target containers, and sets both ends up from the recipe. `lab panel` prints a link with a one-time token; open it to get a console in the client and in the server, the live capture, the path impairments and the censor. Pick **Russia (TSPU)** under Censor and apply it to see what the model does to the tunnel.

```bash
wirelab lab down
```

stops the containers; folders and recorded sessions stay.

## First test run

```bash
wirelab lab test scenarios/lab/smoke.toml
```

One cell, a few workloads, a report in `runs/lab-smoke-<time>/report.md`. See [Lab tests](lab-tests.md) for writing your own.

## Next

- [Lab](lab.md): addresses, folders, the panel, session archives.
- [Recipes](recipes.md): the ones shipped and how to write one.
- [Lab tests](lab-tests.md): scenario reference.
- [Censor](censor.md): rules, presets, sources.
