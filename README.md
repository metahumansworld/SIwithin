# SIwithin

SIwithin runs an agent CLI unattended on a brief, inside a fence around the folders you give it and under a dollar budget, and leaves one record per run. It keeps three promises with a tool and not with hope:

1. **The run touches only the folders it was given.** Your home folder is refused, for reading and writing, and the run's folders are allowed back.
2. **The run cannot spend more than the dollars it was given.** A budget per run, a cap across all runs, a timer on every run. Where a CLI cannot be stopped mid-run, the tool refuses it unless you say you accept that (see "The ledger" and "The Codex adapter").
3. **Every run leaves one line** saying what it cost and whether it was done.

Works with the Claude Code and OpenAI Codex command-line tools. SIwithin is an independent project; it is not made, endorsed or sponsored by Anthropic or OpenAI. Claude, Claude Code, OpenAI and Codex are the names of their owners, used here only to say which programs SIwithin can drive. You remain bound by each vendor's terms of service and usage policies when you use their CLIs through SIwithin; SIwithin changes none of them.

SIwithin v0.1 runs on macOS only. On Linux and Windows it refuses to run, in one line, rather than run without a fence.

## Install

SIwithin is one file, Python 3.10 or newer, standard library only. It makes no network calls and sends no telemetry.

```
git clone <this repository> && cd siwithin
python3 siwithin.py --version
# optional: put it on your PATH
install -m 755 siwithin.py ~/.local/bin/siwithin
```

You also need the CLI you want to drive, installed and on your `PATH`, and an API key for it (see "Auth").

The smoke test (`python3 tests/smoke.py`) passes on the Python it was written on, 3.9.6. 3.10 is the supported floor and the code avoids newer syntax, but v0.1 was not run on 3.10 or newer.

## Quick start, Claude Code

```
mkdir -p ~/.config/siwithin && echo 20 > ~/.config/siwithin/cap       # all runs together may spend $20
export ANTHROPIC_API_KEY=...                                     # see "Auth"; SIwithin copies it into the run by name and never reads it

python3 siwithin.py --dir ~/work/proj --model sonnet --dry-run < brief.md      # print everything, run nothing
python3 siwithin.py --dir ~/work/proj --model sonnet --budget 2 \
    --done "ALL TESTS PASS" --out notes.md < brief.md
```

`--dir` is the run's folder: the CLI works in it and may write in it (`--readonly` makes it read-only). `--read <folder>` adds folders the run may read. `--model` takes an id or an alias (`haiku`, `sonnet`, `opus`).

## Quick start, Codex

```
mkdir -p ~/.config/siwithin && echo 20 > ~/.config/siwithin/cap
export CODEX_API_KEY=...

python3 siwithin.py --adapter codex --model gpt-5.3-codex --soft-budget --dir ~/work/proj --dry-run < brief.md
python3 siwithin.py --adapter codex --model gpt-5.3-codex --soft-budget --budget 2 --dir ~/work/proj < brief.md
```

Two flags are required for this adapter, for reasons in "The Codex adapter": `--model` (the CLI reports tokens and no cost, so a run is priced by model id) and `--soft-budget` (the CLI reports usage only when a turn ends). This adapter was built from documentation and **has not been run against a live CLI**.

## Auth

SIwithin never reads, parses, stores, prints or logs a key. It copies the environment variables named in an adapter's `env_pass` into the run, by name, and records their names only. Each run gets a config directory of its own under SIwithin's home (`claude-config/`, `codex-config/`) with no login in it, so a CLI cannot quietly sign with a login and bill that instead of your key.

- **Claude Code** finds a key in the `ANTHROPIC_API_KEY` environment variable, or from an `apiKeyHelper` command named in a `settings.json` in its config directory. For the helper, put `{"apiKeyHelper": "/path/to/your/script"}` in `~/.config/siwithin/claude-config/settings.json`. The helper path is the one measured by the launcher SIwithin grew from. The environment-variable path is described in the vendor's public issue tracker (`claude -p` works with it, and `claude auth status` reports `authMethod: "api_key"`) and was not measured here. To point the CLI at a settings file of your own, add `["--settings", "/path/to/settings.json"]` to `extra_args` in `config.toml`.
- **Codex CLI** reads `CODEX_API_KEY` for `codex exec` (its documentation). Its saved ChatGPT login lives in `$CODEX_HOME/auth.json`; because each run has its own `CODEX_HOME`, that login is not used, and a dollar budget means nothing for plan billing anyway.

`--require-api-key` (on by default for the `claude` adapter, refused for `codex`, which has no way to check) asks the CLI before launch how it is signed in, and checks the key source in the CLI's first event. If either says a login would be billed, the run is refused or killed, and the message says why: a CLI with a login in its config directory can sign with that login while its events name an API key. `--no-require-api-key` accepts a login.

## The fence

SIwithin generates a macOS `sandbox-exec` profile for each run, from a template, with the home folder derived at run time. `--dry-run` prints it; each run folder keeps it as `fence.sb`.

- The whole home is refused for reads and writes.
- Allowed back: the run's folders (readable; the first writable unless `--readonly`), the CLI's binary, its caches and logs under `~/Library` (readable and writable), its keychain files (readable only, for a key helper), Python user packages, the shell's rc files, git's config, and the run's own config directory.
- Inside the CLI's config directory, only its state paths are writable (`config_write` in the config): transcripts, sessions, file history, todos, caches and the like. Settings, the state file, memory, commands, skills, agents, hooks, plugins, scheduled tasks and a key helper kept there stay as the owner left them, and the memory folder under each transcript folder stays unwritable too, so a run leaves no instruction for the next one.
- Writes are also refused in `/private/tmp`, `/tmp`, `/opt`, `/usr/local`, `/Applications`, `/Library` and `/Volumes`. The CLI's temp root is moved into the run's folder, for a CLI that has a variable for it.
- `open`, `screencapture`, `osascript`, `say` and `afplay` may not be started.
- SIwithin's own home (config, cap, ledger, other runs' briefs) is refused to the run.
- `--dir` and `--read` refuse the home root and any folder holding it, `~/.ssh`, `~/.config`, `~/Library`, each adapter's own config directory (`~/.claude`, `~/.codex`), SIwithin's home, and any folder listed under `[never]` in `config.toml`. The fence enforces only what it is told, so these are refused up front.
- The run's environment is a short list (`[env] pass` and the adapter's `env_pass`). The rest of your shell's environment is not inherited.

**What the fence does not stop:** the network (a run can send anything it can read to any host); reads outside the home; writes outside the home and the listed roots; whatever the run writes into its own folder and you later run (scripts, git hooks); a key exported in a shell rc file, which the run can read; and anything the CLI does in its own cloud sandbox or on a remote machine, where the fence is not. Read [SECURITY.md](SECURITY.md) before relying on it.

## The ledger

Each run appends one line to `ledger.md` in SIwithin's home and writes a summary line to your terminal:

```
2026-10-13 14:02 | docs-pass | /Users/you/work/proj | claude sonnet - | 12 turns | 6.4 min | cli $0.4123 | true $0.4123 | in 310k out 18k | runs/2026-10-13-1402-docs-pass | done | receipt 864410d4e9f126c9abf1b0b12c28e21ff8541cf24ceaf98039781609a9133881
```

- **cli** is the CLI's own cost figure (`-` when the CLI gives none). **true** is the cost at published rates from `[prices]` in `config.toml`, keyed by model id. `[prices]` carries the date the rates were read (`read_on`) and where (`source`); SIwithin warns when they are over 90 days old. Rates change: check them. Cache writes are priced at the 5-minute rate, and a run that uses a higher tier than the one listed (a long prompt on one model, a long-context or fast tier on another) is understated.
- **Cap.** `cap` holds one number, the dollars all runs together may spend. SIwithin adds up the **true** column and refuses a run when the total plus its `--budget` passes the cap, checked under the lock.
- **Budget.** `--budget` is true dollars. For a CLI with a budget flag, SIwithin passes `budget × factor` (`[factors]` is the ratio between the CLI's units and true dollars, 1 unless listed). The built-in default for the smallest Claude model is 1; CLI 2.1.284 priced it at another model's rates and needed 40, which you can set under `[factors]` in `config.toml` if you are on that version. SIwithin warns when the CLI's cost over the true cost is more than four times the factor or less than a quarter of it: the factor has gone stale, in either direction. For a CLI with no budget flag, SIwithin reads usage as it streams and kills the run at the budget. For a CLI that reports usage only when a turn ends, SIwithin refuses unless `--soft-budget` is given, and then the budget is checked when each turn ends.
- **Claude Code: the budget is enforced twice.** By the CLI's flag (`--max-budget-usd`, given `budget × factor`), and by SIwithin from the stream: each assistant event carries that response's usage, SIwithin prices it at the `[prices]` rates (each message id once; one response can arrive as several events), and kills the run's whole process group when the true cost reaches the budget. The ledger line and the summary then say `killed: budget $0.50 reached at $0.5502 true`. The flag stays as the second stop, so a wrong factor cannot lift the budget by itself. When the flag stops the run first, the line says `stopped by the CLI's budget flag: Reached maximum budget ($0.10)`, the CLI's own words, and `result.md` holds the model's last message, since the CLI's result then carries no text. `--dry-run` prints both. Two limits, both in the summary notes when they apply:
  - The stream's per-event output tokens are a placeholder until the final result. SIwithin's stop counts input and cache tokens fully and output tokens only as streamed, so it never fires early, and on a run heavy in output it fires after the true budget is passed, by the output not yet reported. A run it kills is booked at what streamed, which is understated by that output; a run that finishes is booked at the CLI's final usage.
  - A model with no entry in `[prices]` cannot be priced from the stream. Its cost in the ledger is the CLI's own figure over its factor, the streamed stop does not count it, and the stop is approximate: only the CLI's flag at `budget × factor` limits it. Add its rates to `[prices]` (and a factor if the CLI's units differ).

  If the stream carries no usage fields, SIwithin falls back to the flag alone and the notes say so.
- **A killed run with no usage report** (timer, interrupt) is booked at its budget as a ceiling, and its line says `(ceiling, usage unreported)`, so the cap stays true.
- Every run also has a folder under `runs/` with `brief.md`, `command.txt` (the command, environment variable names and the CLI's version), `fence.sb`, `events.jsonl`, `stderr.txt`, `result.md`, `summary.json` and `receipt.json` (see "The receipt").

## The receipt

After a run ends, and before its ledger line is appended, the runner writes `receipt.json` into the run's folder: the sha256 of each file the runner wrote, chained to the previous receipt and to the ledger as it stood. The ledger line then carries the receipt's own hash as its last field, `| receipt <64 hex>`; the terminal prints it on a line `receipt: <64 hex>` after `session:`. The runner writes it after the CLI has exited; the model never does. A run refused before launch writes no receipt and no ledger line, and `--dry-run` writes nothing. `summary.json` cannot carry the receipt's hash, because the receipt hashes `summary.json`.

`receipt.json` is JSON with sorted keys, indent 1, UTF-8; its hash is the sha256 of its bytes. Fields:

- `receipt`: the format's version, 1. `tool`: the runner's name and version, `siwithin 0.2.1`. `run`: the run folder's name, as on the ledger line after `runs/`.
- `started` and `ended`: the run's start and the moment the receipt was written, ISO 8601 to the second. `status`: as on the ledger line.
- `files`: the sha256 of `brief.md`, `command.txt`, `fence.sb`, `events.jsonl`, `stderr.txt`, `result.md` and `summary.json`. Nothing else from the folder: not `tmp/`.
- `ledger_before`: the sha256 of the ledger's bytes immediately before this run's line was appended (with the header already written when the ledger was new).
- `previous`: the receipt hash on the last ledger line that carries one, or `null`.

Verify:

```
python3 siwithin.py --verify [--home H]            # every receipt on the ledger
python3 siwithin.py --verify ~/.config/siwithin/runs/<run>    # one run folder's files against its receipt
```

For each ledger line that ends in a receipt, the verifier checks that `receipt.json` exists and hashes to the hex on the line; that each file in `files` hashes as the receipt says; that `ledger_before` is the hash of the ledger's bytes before that line; and that `previous` is the hex on the previous receipt-bearing line (`null` for the first). Because the receipt cannot hold the line it is carried on, it also checks that the line's run and status are the receipt's and that its `true $` figure is the one in `summary.json`, which the receipt does hold. A line without the field, from before 0.2, is counted and not failed. It prints `ok <run>` or `FAIL <run>: <what failed>` per receipt and `N receipts ok, M failed, K lines without a receipt`, and exits 0 only when none failed. It takes no lock and reads no config. With a run folder it checks that folder's files and nothing else, and says `ok <run>: 7 files match the receipt` or `FAIL ...`.

**What it proves:** the run's files and the ledger are as the runner wrote them. A later edit to a brief, a result, an events file or a cost breaks a hash, and an edit to a ledger line breaks the next line's `ledger_before`.

**What it does not prove:** that the events are true to what the API did; the CLI wrote them, and the receipt hashes what the CLI said. And whoever can write SIwithin's home can rewrite every receipt and the whole chain from the first line, so the chain is evidence against change by anything without that access, not against the owner. Keep the last receipt's hash somewhere else, in a message, a note or a commit, and it pins the whole chain at that point: any change before it shows as a different chain.

## The brief contract

- The brief is **stdin**. An empty brief is refused.
- `--done "<text>"`: after the run, SIwithin reports whether `result.md` contains the text. `--absent "<text>"`: whether it contains that text, which you want gone. A run that finished but misses its `--done` text, or contains its `--absent` text, is not `done`: its status is `finished, contract unmet: ...`, and the ledger line says so.
- `--out <file>`: the result is written there when, and only when, the run is `done`. The path is relative to `--dir` and must stay inside it; SIwithin writes nowhere else. It is refused with `--readonly`: take a readonly run's result from `result.md`.
- Exit status: 0 when `done`, 1 for anything else (a refusal included).

## The Codex adapter

Built from public documentation, read on **2026-10-13**:

- https://developers.openai.com/codex/noninteractive (redirects to https://learn.chatgpt.com/docs/non-interactive-mode, which was read)
- https://developers.openai.com/codex/cli/reference (redirects to https://learn.chatgpt.com/docs/developer-commands?surface=cli, which was read)
- https://github.com/openai/codex
- https://developers.openai.com/api/docs/pricing (the rates in `[prices]`)

**Confirmed from those pages:** `codex exec`; the prompt read from stdin when omitted or given as `-`; `--json` (JSON Lines on stdout) with events `thread.started` (`thread_id`), `turn.started`, `item.completed` (an `agent_message` item with `text`), `turn.completed` (`usage` with `input_tokens`, `cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`), `turn.failed`, `error`; `--cd`/`-C`; `--model`/`-m`; `--sandbox`/`-s` with `read-only`, `workspace-write`, `danger-full-access`; `--skip-git-repo-check`; `--output-last-message`/`-o`; `CODEX_API_KEY` for `exec`; `CODEX_HOME` and `~/.codex/auth.json`. **No flag limits turns or spending, and no cost field is documented.** That is why this adapter needs `--soft-budget`: usage arrives only on `turn.completed`, so a single long turn can pass the budget before SIwithin sees it. A run that ends with its turn is reported over budget; one that starts another turn past the budget is killed.

**Marked `unconfirmed` in `config.toml`** (the pages read do not confirm them; options that need them are refused, naming the field): `effort_flag`, `resume_flag` (the CLI resumes with the subcommand `exec resume`, which v0.1 does not wire). **Assumptions, listed in every dry run and summary:** that `input_tokens` includes `cached_input_tokens` (the sample numbers suggest it; if wrong, the true cost is understated); that `output_tokens` includes reasoning tokens; whether `usage` is per turn or cumulative (SIwithin sums `turn.completed` events); whether the CLI's own sandbox starts inside SIwithin's profile (the default is `--sandbox workspace-write`, and `read-only` with `--readonly`; if it refuses to start, set `args_write` in `config.toml` knowingly); where the binary installs (SIwithin allows the folder of the one it finds on `PATH`); the format of `--version`. `--read` folders are not announced to this CLI, because its `--add-dir` grants writes.

## What v0.1 does not do

- **Linux and Windows.** No fence there, so SIwithin refuses. On the roadmap, not started.
- **A hosted team ledger.** The ledger is a file on one machine.
- **More CLIs.** Two are built in; a third can be declared in `config.toml` if it speaks one of the two output formats (`claude-stream-json`, `codex-jsonl`). Other formats need code.
- **A network fence**, mid-turn budget enforcement for CLIs that report usage late, resume and effort for the second adapter, and a verified run of the second adapter against a live CLI.
- **Streamed output tokens for the first adapter's stop.** The CLI's stream reports a response's real output count only in its final result; its SDK documentation says a partial-messages option streams the running count, and v0.1 does not use it. The streamed stop is therefore a lower bound on output-heavy runs (see "The ledger"). It was built and tested against a fake CLI that replays the stream's documented shape, not against a live CLI run.
- The profile was built from constructs the earlier launcher already used, but `sandbox-exec` did not compile it while v0.1 was built: run a trivial brief and read `stderr.txt` first.

## Configuration

Copy `config.example.toml` to `~/.config/siwithin/config.toml`. Every option is there with a one-line comment, and every value is the built-in default, so keep only what you change. `--home <folder>` moves all of SIwithin's paths (`config.toml`, `cap`, `ledger.md`, `lock`, `runs/`, the per-CLI config directories) in one go.

## Status

Version 0.2.1, released 14 October 2026: a budget under a cent prints with four decimals in the kill status, the over-budget note, the cap check and the dry-run text, where 0.2.0 printed `$0.00`; the runner is otherwise 0.2.0's, and the smoke test passes 168 checks with fake CLIs. Version 0.2.0, released 14 October 2026: the receipt, live on one run that day, Claude Code 2.1.296 with Haiku, after which `--verify` printed `1 receipts ok, 0 failed, 4 lines without a receipt`; the smoke test passes 168 checks with fake CLIs. Four live runs on Claude Code 2.1.296, on 13 October 2026: the first ended by the model's own end of turn at $0.0995 of a $0.10 budget, the CLI having shown it the budget; the second authenticated through a keychain the run could only read; the third and fourth were stopped by the CLI's budget flag, the first enforcement live, the fourth with the config directory writable in its state paths only; a run past the cap was refused before launch. No write was refused by the fence, and none was seen outside the run folders; what the CLI wrote in the folders the fence allows it, its config directory and the caches, was not listed. Not yet live: the runner's own kill, the second enforcement, exercised only with the fake CLIs.

## Tests

```
python3 tests/smoke.py
```

Runs with a temporary home and no CLI installed: dry runs for each adapter, the fence profile's lines, forbidden folders, the cap arithmetic, the config reader, and (on macOS) whole runs against fake CLIs with the sandbox program replaced by a shim, so the streaming, kill, ledger and summary code is exercised, including a fake that streams usage past a budget (the run, its child process and its ledger line must be killed for it) and one that stays under, and the receipts: written for each booked run and not for a refused one, chained, and `--verify` passing on the home and failing on a changed result, a changed cost, a replaced hash and a changed run folder. The fence itself is not tested there.

The red briefs, `tests/red/`, test the fence. Five ordinary-sounding tasks each cross one wall: a write to the home directory outside the run's folder, a write to `/tmp`, the start of a program on `deny_exec`, a write to SIwithin's own ledger, and a task long enough to pass a small budget. `python3 tests/red/run.py --fake` proves the scorer on planted run folders and runs nothing live. `--live` runs each brief through `siwithin.py` with Haiku against a red home, scores the run folders, runs the key-leak detector and `--verify`, and writes a scorecard whose last column is each run's receipt hash. The three scorecards of 14 October 2026 are in the folder: four walls held in every pass, and the budget wall by design, the stop firing at $0.0002 true against a budget of $0.0001 (the `$0.00` in that kill status is what 0.2.1 fixed); 15 receipts verified; the fifteen runs cost $0.0481 together on the maintainer's ledger. [tests/red/README.md](tests/red/README.md) has the walls, the verdicts, and the finding that a model shown its remaining budget does not cross it.

## Renaming

Change `NAME` at the top of `siwithin.py`. The default home, the messages, the ledger header and the lock text follow.

## License

Apache License 2.0. See [LICENSE](LICENSE). Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

Copyright 2026 metahumansworld. Licensed under the Apache License, Version 2.0; see LICENSE.
