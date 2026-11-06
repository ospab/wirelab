# Contributing to wirelab

[Русский](CONTRIBUTING.ru.md) · [README](README.md) · [Documentation](docs/README.md)

Thank you for helping. The bench is only as useful as its censor model is honest and its measurements are right, so most of what follows is about those two things.

## Most wanted

1. **Field observations that correct a preset.** If a rule in `containers/censor/presets/` behaves differently from what you measured on a real network, open an issue with the operator, region, date, connection type, what you did and what happened, and a capture if you can share one. A preset changes when the published evidence does.
2. **Reference captures.** A small capture that a rule must block and one it must not (see the [roadmap](docs/ROADMAP.md)). Strip anything that identifies you first.
3. **Recipes** for more protocols (Hysteria 2, NaïveProxy, AnyTLS, Tor pluggable transports…): see [Recipes](docs/en/recipes.md).
4. **Presets for other censors** (China, Iran…), under the same rules as the Russian one.
5. Bugs, with what you ran and its output; for lab problems, `wirelab doctor` and a session archive (`wirelab lab export`) help most.

## Rules for the censor model

- **Every rule cites its source**: a paper, a report, a forum post, with a link and a date, and a short quotation of the observation it reproduces. A rule without one does not load.
- **What the sources do not settle is a hypothesis**, not a silent choice. Add it to the preset's `hypotheses` with the observations on each side, and pick the stronger censor as the default unless the evidence says otherwise.
- **Your own choices are named as such.** A window or threshold the sources leave vague goes in, with "this preset's choice" in the source text.
- **Lists of names and addresses are examples.** Do not add lists scraped from real registries; they change daily and are not what the model is about.

## Rules for measurements

- An outcome is `PASS`, `FAIL` or `NO DATA`. A check that could not measure reports `NO DATA` with the reason, never a guessed or default value, and is never counted as a pass.
- A threshold belongs to the scenario, not to the code. When a standard (CRTS) leaves a threshold to the profile, the code reports the measurement and `NO DATA` until the scenario gives one.

## Development

You need what [Getting started](docs/en/getting-started.md) lists. Before sending a change:

```bash
cargo build --release
cargo test --release --workspace
```

The censor, from `wirelab-censor/`:

```bash
gofmt -l .                 # prints nothing when formatted
go vet ./...
go test ./...
```

Changes to the nDPI binding (`ndpi_linux.go`) or the rules it feeds are checked by `wirelab censor build`, which runs the tests inside the build container against nDPI's own test captures.

The panel is one HTML file with its script inline (`wirelab-lab/src/panel.html`). Check the script with `node --check` on the last `<script>` block, and open the panel in a browser for anything visible. Its look follows [DESIGN.md](DESIGN.md).

For changes that touch the lab (recipes, workloads, the runner), run `wirelab lab test scenarios/lab/smoke.toml`, or `recipes.toml` for recipe changes, and say in the pull request what it reported.

## Style

- Match the code around your change: its naming, its comment density, its line length. Comments say why, not what.
- Shell scripts that run in containers are POSIX `sh` with LF line endings (`.gitattributes` enforces it).
- Commit messages: one imperative line that says what changed ("Add QUIC SNI rule from FOCI 2026"), and a body when the reason is not obvious.
- Documentation comes in English and Russian (`docs/en`, `docs/ru`); if you write only one, say so in the pull request and someone will add the other.

## Security and safety

- Do not post working server addresses, keys or subscription links in issues, captures or scenarios.
- The panel serves root shells into the lab; report anything that lets a page or another local user reach it without the token privately, through GitHub's private vulnerability reporting, rather than in a public issue.

## Licence

wirelab is licensed under the GNU Affero General Public License v3.0 only. By contributing you agree that your contribution is licensed under the same terms. Third-party code must come under a compatible licence and be listed in [NOTICE.md](NOTICE.md).
