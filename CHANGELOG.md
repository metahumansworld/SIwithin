# Changelog

## v0.2.0, 2026-10-14

- 2026-10-14: released. The receipt ran live on one run on Claude Code 2.1.296 and verified (README, Status). SECURITY.md: the reporting address is siwithin@metahumans.world, the receipt is in what the tool protects and in what to report, and the "not verified" list is brought up to the live runs.
- 2026-10-13: the receipt. After a run ends, before its ledger line is appended, the runner writes `receipt.json` into the run's folder: the sha256 of the seven files it wrote, `ledger_before` (the hash of the ledger as it stood) and `previous` (the last receipt's hash), so the runs form a chain. The ledger line gains a last field, `| receipt <64 hex>`, and the terminal a line `receipt: <64 hex>` after `session:`; every other field of both is as it was. New `--verify [RUN]`, which needs no `--dir`, takes no lock and reads no config: with no argument it checks every receipt on the ledger, with a run folder it checks that folder's files; exit 0 only when nothing failed. Ledger lines from before 0.2 are counted, not failed. `--version` is now `siwithin 0.2.0`.
- The CLI's config directory is writable in its state paths only, `config_write`, a new fence key: transcripts, sessions, file history, todos, caches and the like. Settings, the state file, memory, commands, skills, agents, hooks, plugins, scheduled tasks and a key helper kept there are refused for writing, and so is the memory folder under each transcript folder. Found on 13 October 2026 by four runs of the CLI against a throwaway config directory with no credentials: it reaches its first API call with all of those refused, writing only a transcript and a sessions folder. Confirmed by the live run of 18:08 the same day: 16 turns of the Write tool under the rule, nothing on stderr.
- The CLI's own budget stop, a result of subtype `error_max_budget_usd`, is named `stopped by the CLI's budget flag: <the CLI's words>` on the summary line, in summary.json and on the ledger line. It printed `api error None: ` in the third live run of 13 October 2026, 17:36, the first time the flag fired live, because the result mapping knew no name for it. Any other stop of the CLI's is named `stopped by the CLI, <subtype>: <its words>`, and `api error` is kept for the API's own failures. When the CLI's result carries no text, as it does then, result.md holds the model's last message from the stream and the notes say so.
- The fence no longer allows writes under `~/Library/Keychains`; the folder stays readable, for the key helper. At the owner's word "read-only keychain" of 13 October 2026, on the fork's finding in test 4 that whether a run may write there was the owner's to judge. Confirmed by the live run of 17:32 the same day: the helper found the key with the keychain read-only.
- The summary line prints the cap with two decimals. It printed "of cap $0" for a cap of $0.20, found in the first live run on 13 October 2026; the ledger line was right.

## v0.1.2, 2026-10-13

### Changed
- Renamed from fence to SIwithin. The command, file and package are `siwithin` (`siwithin.py`); `--version` prints `siwithin 0.1.2`. What the tool builds around a run is still called a fence.
- The config home moved to `~/.config/siwithin/`. A home at `~/.config/fence/` is not read: move it, or point `--home` at it.
- No behaviour change.

## v0.1.1, 2026-10-13

Closes a gap found in a dry run of v0.1.0: with the first adapter the budget was kept by the CLI's flag at `budget × factor`, and the default factor of 40 for the smallest model, inherited from CLI 2.1.284, let a run launched on CLI 2.1.296 (whose own cost is the true cost) spend forty times its budget before the CLI stopped it.

### Changed
- The first adapter now enforces the true budget itself as well. The usage on each assistant event in the CLI's stream (input, cache-creation, cache-read and output tokens, and the model) is priced at the `[prices]` rates as it streams, each message id once, and the run's process group is killed when the true cost reaches `--budget`. The ledger line and the summary say `killed: budget $X reached at $Y true`. The CLI's flag stays as a second stop. If the stream carries no usage fields, the flag alone enforces the budget and the summary notes say so. (`usage_at = "message"` in the adapter.)
- The default factor for the first adapter's smallest model, `claude-haiku-5-5`, is 1. CLI 2.1.284 needed 40; a user on that version sets it under `[factors]` in `config.toml`. The comment saying so is in `fence.py` and `config.example.toml`.
- The stale-factor warning is two-sided: it fires when the CLI's cost over the true cost is more than four times the factor or less than a quarter of it.
- `--dry-run` prints both enforcements for the first adapter: the flag with its factor, and the streamed true-cost stop.
- The budget stop for adapters without a budget flag now uses the same wording, `killed: budget $X reached at $Y true`.
- `summary.json` gains `stream_cost`, the true cost of what streamed.

### Known limits, stated in the README and SECURITY.md
- The stream's per-event `output_tokens` is a placeholder until the final result, so the streamed stop is a lower bound: it never fires early and, on a run heavy in output, fires after the true budget. A run it kills is booked at what streamed.
- A model with no entry in `[prices]` is not counted by the streamed stop: the CLI's figure over its factor is used in the ledger and only the CLI's flag limits the run, so the stop is approximate.

### Tests
- `tests/smoke.py` adds a fake CLI that streams assistant events with usage: a run that passes the budget is killed (with its child process and the exact reason in the ledger line), a run under the budget is not, and the fallbacks (no usage in the stream, a model with no price) are noted. The test's choice of the latest run folder no longer breaks when more than nine runs share a minute.

## v0.1.0, 2026-10-13

First release: a standalone, vendor-neutral runner, built from a single-CLI launcher that ran on one person's Mac.

### Added
- `fence.py`, one file, Python 3.10+, standard library only. No telemetry and no network calls from the tool itself.
- Adapters declared in `config.toml`, with two built in (the README names the CLIs): the first, its command shape measured on CLI 2.1.284 and 2.1.296 by the launcher this grew from; the second, built from documentation read on 2026-10-13 and not run against a live CLI.
- The fence: a macOS `sandbox-exec` profile generated from a template with the home derived at run time. The home is refused for reads and writes and allowed back for the run's folders, the CLI's binary, caches, logs and keychain, the shell's rc files, git's config and the CLI's own config directory. The tool's own home is refused inside the run.
- Refusal of the home root (and any folder holding it), `~/.ssh`, `~/.config`, `~/Library`, each adapter's own config directory, the tool's home and any `[never]` folder, as `--dir` or `--read`, compared case-insensitively.
- On Linux and Windows the tool refuses to run, in one line, and points to the roadmap. `--dry-run` still prints everything on Linux and reports the refusal.
- Budget and cap: `--budget` per run, a `cap` file across all runs, checked under the lock. True cost at published rates from `[prices]` (with the date they were read), beside the CLI's own figure; `[factors]` with a stale-factor check, in both directions.
- Budget kept by the CLI's flag where it has one; kept by the runner from streamed usage where it does not. For a CLI that reports usage only when a turn ends, the tool refuses unless `--soft-budget` is given.
- A killed run whose usage was never reported is booked at its budget as a ceiling, and the ledger line says so.
- One run at a time (lock file), `--timeout` by a timer always, a run folder per run (`brief.md`, `command.txt`, `fence.sb`, `events.jsonl`, `stderr.txt`, `result.md`, `summary.json`), one ledger line per run, and a summary line.
- Brief contract: brief on stdin, `--done`, `--absent`, `--out` (inside `--dir` only).
- `--require-api-key` (default on for the first built-in adapter): the CLI's auth status before launch and the init event's key source during it.
- `--dry-run`: the resolved command, the fence profile, the config checks and the budget arithmetic; nothing is run or written.
- A reader for the TOML subset the config uses, for Python 3.10; `tomllib` is used where it exists.
- `tests/smoke.py`, `config.example.toml`, `README.md`, `SECURITY.md`, `LICENSE` (Apache-2.0).

### Not in v0.1
- Linux and Windows; a hosted team ledger; more CLIs; resume and effort for the second built-in adapter; a network fence. See the README.
