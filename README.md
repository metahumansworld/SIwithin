# SIwithin

SIwithin runs an agent CLI unattended on a brief, inside a fence around the folders you give it and under a dollar budget, and leaves one record per run. It keeps three promises with a tool and not with hope:

1. **The run touches only the folders it was given.** Your home folder is refused, for reading and writing, and the run's folders are allowed back.
2. **The run cannot spend more than the dollars it was given.** A budget per run, a cap across all runs, a timer on every run, and, for the Claude adapter, a loopback proxy that is the one door to the API: the run holds a per-run token and not your key, and every request it makes, however it makes it, is metered there and refused past the budget. Where a CLI cannot be stopped mid-run, the tool refuses it unless you say you accept that (see "The ledger" and "The Codex adapter").
3. **Every run leaves one line** saying what it cost and whether it was done.

Works with the Claude Code and OpenAI Codex command-line tools. SIwithin is an independent project; it is not made, endorsed or sponsored by Anthropic or OpenAI. Claude, Claude Code, OpenAI and Codex are the names of their owners, used here only to say which programs SIwithin can drive. You remain bound by each vendor's terms of service and usage policies when you use their CLIs through SIwithin; SIwithin changes none of them.

SIwithin runs on macOS only. On Linux and Windows it refuses to run, in one line, rather than run without a fence.

## Install

SIwithin is one file, Python 3.10 or newer, standard library only. It makes no network calls of its own and sends no telemetry; the proxy it starts for a run listens on a loopback port and talks only to the API host you configure.

```
git clone <this repository> && cd siwithin
python3 siwithin.py --version
# optional: put it on your PATH
install -m 755 siwithin.py ~/.local/bin/siwithin
```

You also need the CLI you want to drive, installed and on your `PATH`, and an API key for it (see "Auth").

The smoke test (`python3 tests/smoke.py`) passes on the Python it was written on, 3.9.6. 3.10 is the supported floor and the code avoids newer syntax, but it has not been run on 3.10 or newer.

## Quick start, Claude Code

```
mkdir -p ~/.config/siwithin && echo 20 > ~/.config/siwithin/cap       # all runs together may spend $20
export ANTHROPIC_API_KEY=...                                     # see "Auth"; the tool reads it once, outside the fence, and the run gets a per-run token in its place

python3 siwithin.py --dir ~/work/proj --model sonnet --dry-run < brief.md      # print everything, run nothing
python3 siwithin.py --dir ~/work/proj --model sonnet --budget 2 \
    --done "ALL TESTS PASS" --out notes.md < brief.md
```

`--dir` is the run's folder: the CLI works in it and may write in it (`--readonly` makes it read-only). `--read <folder>` adds folders the run may read. `--model` takes an id or an alias (`haiku`, `sonnet`, `opus`).

## Quick start, Codex

```
mkdir -p ~/.config/siwithin && echo 20 > ~/.config/siwithin/cap
export CODEX_API_KEY=...

python3 siwithin.py --adapter codex --model gpt-5.3-codex --soft-budget --network open --dir ~/work/proj --dry-run < brief.md
python3 siwithin.py --adapter codex --model gpt-5.3-codex --soft-budget --network open --budget 2 --dir ~/work/proj < brief.md
```

Two flags are required for this adapter, for reasons in "The Codex adapter": `--model` (the CLI reports tokens and no cost, so a run is priced by model id) and `--soft-budget` (the CLI reports usage only when a turn ends). This adapter was built from documentation and **has not been run against a live CLI**. It runs with `auth = "env"`: the key is in the run's environment (see "Auth"), and since there is no proxy there is no port for the network wall to allow, so it needs `--network open`, or `network = "open"` under `[fence]` in `config.toml`; under the default the run is refused rather than run with no network (see "The fence").

## Auth

SIwithin never parses, stores, prints or logs a key, and writes one into no file, log line or error message. How the key reaches the API depends on the adapter's `auth` field.

**The Claude adapter, `auth = "proxy"` (the default from 0.3.0).** Before launch, outside the fence, the runner reads the key once: from `ANTHROPIC_API_KEY` in its own environment, or else from the first line printed by `[auth] key_command` in `config.toml`, a command of yours that prints the key (a keychain lookup, for example). It keeps the key and starts a small HTTP server on a loopback port of its own, standard library only. The run's environment holds `ANTHROPIC_API_KEY=siwithin-<32 characters>`, a token new for every run and worth nothing elsewhere, and `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`. Every request the run makes, by the CLI, by hand or by a second CLI it starts, passes that door: the proxy takes only the run's token (anything else gets 401 and goes nowhere), forwards only the paths on `[auth] paths` (`/v1/messages` and `/v1/messages/count_tokens` by default; any other path gets 403 and the real key is never attached), adds the real key, relays the response as it streams, and prices each `/v1/messages` response at the `[prices]` rates from its usage. Once the total reaches the budget every later `/v1/messages` request gets 402, the first refusal kills the run's processes as the streamed stop does, and the proxy keeps refusing until the runner exits. When the run ends the proxy is sealed, its log closed and its server shut, so the token is worth nothing. One line per request goes to `proxy.jsonl` in the run's folder (path, model, status, usage, cost, the running total, the client's port, why it was refused; never a body, a key or the token). A `settings.json` in the run's config directory that names `apiKeyHelper` is refused before launch, since the CLI would run the helper inside the fence where the run can read it: put the helper's command in `[auth] key_command` instead, which the runner runs outside the fence. `--dry-run` prints `auth: proxy 127.0.0.1:<port>` and starts nothing.

**`auth = "env"`** copies the key's variable into the run by name, as 0.2.1 did. It is the Codex adapter's only mode and an opt-in for the Claude adapter (the checks warn). In this mode the key is in the run's environment and inherited by every command the run starts, and the network wall cannot be raised, since there is no proxy port to allow: the run is refused under the default `[fence] network = "proxy"` and needs `network = "open"` (or `--network open`), so the run can send the key anywhere and spend with it outside the ledger. Use a key made for SIwithin alone, in a workspace with a spend limit set in the provider's console, and treat it as exposed to whatever text the run reads ([SECURITY.md](SECURITY.md), "Known gaps").

Each adapter gets a config directory under SIwithin's home (`claude-config/`, `codex-config/`), shared by its runs, with no login in it, so a CLI cannot quietly sign with a login and bill that instead of your key.

- **Claude Code** finds a key in the `ANTHROPIC_API_KEY` environment variable and an API address in `ANTHROPIC_BASE_URL`; under the proxy those are the run's token and the loopback port, and the CLI ran so in the live red passes of 14 and 15 October 2026 (Tests). To point the CLI at a settings file of your own, add `["--settings", "/path/to/settings.json"]` to `extra_args` in `config.toml`; one that names `apiKeyHelper` is refused, as above.
- **Codex CLI** reads `CODEX_API_KEY` for `codex exec` (its documentation). Its saved ChatGPT login lives in `$CODEX_HOME/auth.json`; because each run has its own `CODEX_HOME`, that login is not used, and a dollar budget means nothing for plan billing anyway.

`--require-api-key` (on by default for the `claude` adapter, refused for `codex`, which has no way to check) asks the CLI before launch how it is signed in, and checks the key source in the CLI's first event, which under the proxy must be `ANTHROPIC_API_KEY`, the token's variable. If either says a login would be billed, the run is refused or killed, and the message says why: a CLI with a login in its config directory can sign with that login while its events name an API key. `--no-require-api-key` accepts a login.

## The fence

SIwithin generates a macOS `sandbox-exec` profile for each run, from a template, with the home folder derived at run time. `--dry-run` prints it; each run folder keeps it as `fence.sb`.

- The whole home is refused for reads and writes.
- Allowed back: the run's folders (readable; the first writable unless `--readonly`), the CLI's binary, its caches and logs under `~/Library` (readable and writable), its keychain files (readable only), Python user packages, the shell's rc files, git's config, and the run's own config directory.
- Inside the CLI's config directory, only its state paths are writable (`config_write` in the config): transcripts, sessions, file history, todos, caches and the like. Settings, the state file, memory, commands, skills, agents, hooks, plugins, scheduled tasks and a key helper kept there stay as the owner left them, and the memory folder under each transcript folder stays unwritable too, so a run leaves no instruction for the next one.
- Writes are also refused in `/private/tmp`, `/tmp`, `/opt`, `/usr/local`, `/Applications`, `/Library` and `/Volumes`. The CLI's temp root is moved into the run's folder, for a CLI that has a variable for it.
- `open`, `screencapture`, `osascript`, `say`, `afplay`, `launchctl`, `crontab`, `at` and `batch` may not be started (`deny_exec`; by path, so a copy elsewhere is not stopped).
- SIwithin's own home (config, cap, ledger, other runs' folders) is refused to the run, except the adapter's config directory, where the CLI keeps the transcripts of its earlier runs: a run can read those, briefs included (SECURITY.md, "Known gaps").
- `--dir` and `--read` refuse the home root and any folder holding it, `~/.ssh`, `~/.config`, `~/Library`, each adapter's own config directory (`~/.claude`, `~/.codex`), SIwithin's home, and any folder listed under `[never]` in `config.toml`. The fence enforces only what it is told, so these are refused up front.
- The run's environment is a short list (`[env] pass` and the adapter's `env_pass`). The rest of your shell's environment is not inherited.
- The network (the wall, 0.4.0). With the proxy adapter the profile refuses every socket, DNS and binds included, except the key proxy's loopback port (`[fence] network = "proxy"`, the default): the CLI reaches the API through the proxy and nothing else leaves the machine from the run, and a local server on another port is refused too. Each refusal is reported by the kernel under the run's own mark (its folder's name); when the run ends the runner reads the report from the unified log by that mark, twice two seconds apart since the kernel lands its coalesced lines late, and counts it in `summary.json` (`network`: `refused`, by target and by process, the CLI's own pid told from the others', and `late` for what landed between the reads) and on one printed line. `network = "report"` leaves the network open and counts every socket the run opens instead, a survey of how many sockets an ordinary run opens besides the proxy's, on which ports, and whether it binds any (the kernel names a socket by kind and port, `remote:*:443`, or a unix socket by path, never by host); `"open"` is 0.3.0's network, unreported. `--network proxy|report|open` overrides the config for one run. An adapter with `auth = "env"` has no proxy and is refused under `"proxy"`, with the way out named. Run live on 15 October 2026 (Status).
- The run's processes are the runner's to end. While the CLI lives the runner keeps the set of its descendants, and at every stop (budget, timer, interrupt, the CLI's own exit) it reads the process table for any process of yours carrying the run's marker, kills the set, then the group, and looks again until nothing is left, holding the lock until then. `summary.json` says how many it found alive that the group kill alone would not have reached (`outlived`, 0 on a clean run). It needs `ps`; without it the run notes so.

**What the fence does not stop:** what the run sends to the API itself, inside request bodies the proxy relays unread (the model's context is the one way out the wall leaves), and the whole network under `[fence] network = "report"` or `"open"`, which an `auth = "env"` adapter needs; reads outside the home; writes outside the home and the listed roots; whatever the run writes into its own folder and you later run (scripts, git hooks); a key exported in a shell rc file, which the run can read; a process that scrubbed its marker and was re-parented before the walk looked; and anything the CLI does in its own cloud sandbox or on a remote machine, where the fence is not. Read [SECURITY.md](SECURITY.md) before relying on it.

## The ledger

Each run appends one line to `ledger.md` in SIwithin's home and writes a summary line to your terminal:

```
2026-10-13 14:02 | docs-pass | /Users/you/work/proj | claude sonnet - | 12 turns | 6.4 min | cli $0.4123 | true $0.4123 | in 310k out 18k | runs/2026-10-13-1402-docs-pass | done | receipt 864410d4e9f126c9abf1b0b12c28e21ff8541cf24ceaf98039781609a9133881
```

- **cli** is the CLI's own cost figure (`-` when the CLI gives none). **true** is the cost at published rates from `[prices]` in `config.toml`, keyed by model id; with the proxy on, it is the proxy's own total, what left the machine for the API through the one door. `[prices]` carries the date the rates were read (`read_on`) and where (`source`); SIwithin warns when they are over 90 days old. Rates change: check them. Cache writes are priced at the 5-minute rate, and a run that uses a higher tier than the one listed (a long prompt on one model, a long-context or fast tier on another) is understated.
- **Cap.** `cap` holds one number, the dollars all runs together may spend. SIwithin adds up the **true** column and refuses a run when the total plus its `--budget` passes the cap, checked under the lock. `cap`, `--budget` and the config's budget refuse `nan` and `inf`.
- **Budget.** `--budget` is true dollars. For a CLI with a budget flag, SIwithin passes `budget × factor` (`[factors]` is the ratio between the CLI's units and true dollars, 1 unless listed). The built-in default for the smallest Claude model is 1; CLI 2.1.284 priced it at another model's rates and needed 40, which you can set under `[factors]` in `config.toml` if you are on that version. SIwithin warns when the CLI's cost over the true cost is more than four times the factor or less than a quarter of it: the factor has gone stale, in either direction. For a CLI with no budget flag, SIwithin reads usage as it streams and kills the run at the budget. For a CLI that reports usage only when a turn ends, SIwithin refuses unless `--soft-budget` is given, and then the budget is checked when each turn ends.
- **Claude Code: the budget is enforced three times.** By the CLI's flag (`--max-budget-usd`, given `budget × factor`); by SIwithin from the stream (each assistant event carries that response's usage, SIwithin prices it at the `[prices]` rates, each message id once, and kills the run's processes when the true cost reaches the budget); and by the proxy, which prices every `/v1/messages` response at the door, refuses with 402 once the total reaches the budget and kills on the first refusal, so a request the CLI's stream does not show is counted too. The ledger line and the summary say `killed: budget $0.50 reached at $0.5502 true`. When the flag stops the run first, the line says `stopped by the CLI's budget flag: Reached maximum budget ($0.10)`, the CLI's own words, and `result.md` holds the model's last message, since the CLI's result then carries no text. `--dry-run` prints all three. The limits, each in the summary notes when it applies:
  - The stream's per-event output tokens are a placeholder until the final result. The streamed stop counts input and cache tokens fully and output tokens only as streamed, so it never fires early, and on a run heavy in output it fires after the true budget is passed. With the proxy on, the proxy's total is what the ledger books, and a note `stream $x, proxy $y` appears when the two differ by more than a cent and more than 1%.
  - The proxy stops the request after the one that crosses the budget, so one response can pass it by its whole cost; a ceiling check that would refuse a request whose worst case crosses is not built (SECURITY.md, "Known gaps").
  - A model with no entry in `[prices]` cannot be priced from the stream or at the door. Its cost in the ledger is the CLI's own figure over its factor, neither stop counts it, and only the CLI's flag at `budget × factor` limits it. Add its rates to `[prices]` (and a factor if the CLI's units differ).

  If the stream carries no usage fields, SIwithin falls back to the flag and the proxy, and the notes say so.
- **A killed run** is booked at the proxy's total where there was a proxy, and otherwise, when its usage was never reported (timer, interrupt), at its budget as a ceiling, its line saying `(ceiling, usage unreported)`, so the cap stays true.
- Every run also has a folder under `runs/` with `brief.md`, `command.txt` (the command, environment variable names and the CLI's version), `fence.sb`, `events.jsonl`, `stderr.txt`, `result.md`, `summary.json`, `proxy.jsonl` on a run that had a proxy, and `receipt.json` (see "The receipt").

## The receipt

After a run ends, and before its ledger line is appended, the runner writes `receipt.json` into the run's folder: the sha256 of each file the runner wrote, chained to the previous receipt and to the ledger as it stood. The ledger line then carries the receipt's own hash as its last field, `| receipt <64 hex>`; the terminal prints it on a line `receipt: <64 hex>` after `session:`. The runner writes it after the CLI has exited; the model never does. A run refused before launch writes no receipt and no ledger line, and `--dry-run` writes nothing. `summary.json` cannot carry the receipt's hash, because the receipt hashes `summary.json`.

`receipt.json` is JSON with sorted keys, indent 1, UTF-8; its hash is the sha256 of its bytes. Fields:

- `receipt`: the format's version, 1. `tool`: the runner's name and version, `siwithin 0.5.0`. `run`: the run folder's name, as on the ledger line after `runs/`.
- `started` and `ended`: the run's start and the moment the receipt was written, ISO 8601 to the second. `status`: as on the ledger line.
- `files`: the sha256 of `brief.md`, `command.txt`, `fence.sb`, `events.jsonl`, `stderr.txt`, `result.md` and `summary.json`, and of `proxy.jsonl` on a run that had a proxy. Nothing else from the folder: not `tmp/`.
- `ledger_before`: the sha256 of the ledger's bytes immediately before this run's line was appended (with the header already written when the ledger was new).
- `previous`: the receipt hash on the last ledger line that carries one, or `null`.

Verify:

```
python3 siwithin.py --verify [--home H]                        # every receipt on the ledger
python3 siwithin.py --verify --expect <hash> [--home H]        # the same, and the last receipt must be this one
python3 siwithin.py --verify ~/.config/siwithin/runs/<run>    # one run folder's files against its receipt
```

For each ledger line that ends in a receipt, the verifier checks that `receipt.json` exists and hashes to the hex on the line; that each file in `files` hashes as the receipt says; that `ledger_before` is the hash of the ledger's bytes before that line; and that `previous` is the hex on the previous receipt-bearing line (`null` for the first). Because the receipt cannot hold the line it is carried on, it also checks that the line's run and status are the receipt's and that its `true $` figure is the one in `summary.json`, which the receipt does hold. Lines before the first receipt-bearing line are the 0.1 ledger's and are counted, not failed; from the first receipt onward a line without one fails (`FAIL line N: no receipt, after line M had one`). With `--expect <hash>` the last receipt-bearing line's hash must equal the one given, else `FAIL: the last receipt is <hash>, not <expected>`. It prints `ok <run>` or `FAIL <run>: <what failed>` per receipt and `N receipts ok, M failed, K lines without a receipt`, and exits 0 only when none failed. It takes no lock and reads no config. With a run folder it checks that folder's files and nothing else, and says `ok <run>: 7 files match the receipt` or `FAIL ...`.

**What it proves:** the run's files and the ledger are as the runner wrote them. A later edit to a brief, a result, an events file or a cost breaks a hash, an edit to a ledger line breaks the next line's `ledger_before`, and a line cut from the end or a receipt stripped from it fails against a kept hash.

**What it does not prove:** that the events are true to what the API did; the CLI wrote them, and the receipt hashes what the CLI said. And whoever can write SIwithin's home can rewrite every receipt and the whole chain from the first line, so the chain is evidence against change by anything without that access, not against the owner. Keep the last receipt's hash somewhere the ledger's writer cannot reach, in a message, a note or a commit, and `--verify --expect` pins the whole chain at that point: any change before it, and any cut after it, shows.

## Reconcile

The ledger accounts for the key's spend inside runs. Spend on the provider's bill that no run accounts for is the sign of a second user of the key. `--reconcile` reads the provider's usage report for the keys the runs spend and sets it against the ledger, bucket by bucket. It runs nothing, takes no lock and writes no ledger line.

```
python3 siwithin.py --reconcile 2026-10-16 [--until 2026-10-17T09:00] [--bucket 1m|1h|1d] [--home H]
python3 siwithin.py --reconcile 2026-10-16 --csv usage.csv     # the Console's usage export instead of the API
python3 siwithin.py --reconcile 2026-10-16 --every 300         # look again every five minutes
python3 siwithin.py --reconcile 2026-10-16 --dry-run           # the request it would make, the key shown as <key>
```

- **Two ways in.** `[reconcile] admin_key_command` is a command, run outside any fence, whose first line is an Admin API key (from the Console's Admin keys page; not offered to individual accounts). With it SIwithin reads the Usage and Cost API's usage report (`/v1/organizations/usage_report/messages`) for the keys in `[reconcile] api_key_ids`, grouped by key, model and service tier, paged until the report ends. While `api_key_ids` is empty it lists the organisation's keys, `id | name | partial_key_hint`, and refuses, so that you choose. Without an Admin key, `--csv FILE` reads the Console's usage export instead, its columns found by name: a time, the model, uncached input, cache read, cache creation (5-minute and 1-hour when the file has them), output, and web searches when present; a header it cannot match is printed as it is and refused. The export's header had not been seen when this was written: if yours is refused, the printed header is what to send with the report.
- **Dollars.** The provider's tokens are priced at the `[prices]` rates, a one-hour cache write at the cache-write rate times `[prices] cache_write_1h_factor` (1.6, the published ratio), a web search at `web_search`. A model with no entry is shown with its tokens and counted `unpriced`. The runs' side is each proxied request's own cost at its own time, from the run's `proxy.jsonl`; a run without one (another adapter, the 0.1 ledger) is placed whole at its line's time.
- **Verdicts, per bucket.** `unaccounted`: provider spend above `[reconcile] tolerance`, or tokens of an unpriced model, with no run active and no request logged. `over`: a run active and the provider above the runs by more than the tolerance. Else `ok`. The summary line comes last, after `report: <path>`:

  ```
  reconcile: 2026-10-18 18:00 to 2026-10-18 20:30 | provider $0.0872 | runs $0.0272 | unaccounted $0.0600 in 1 buckets | over $0.0000 in 0 | unpriced 0 | key apikey_01Ab…
  ```

  Exit 0 when every bucket is `ok`, 1 when any is `unaccounted` or `over`, 2 when it could not run, with one line `refused: …`. The report, a table per bucket and the provider's results with every token count, goes to `<home>/reconcile/<UTC stamp>.md`, with the same figures as `.json` beside it. `--every SECONDS` (at least 60) looks again at that interval, prints a line when a figure changes and exits 1 at the first unaccounted bucket.
- **The admin key** is held in one object and goes into the request header and nowhere else: not into the report, not into the error text (a 401's message is scrubbed to `<key>`), not into any file. `--dry-run` does not run the command at all.
- **What it does not see.** The report is asked for by key, model and service tier only; spend in fast mode, in the US inference geography or in a long-context tier is priced at the standard rate, so the provider's figure is understated, never overstated. The proxy logs one cache-write count and prices it at the five-minute rate, so a CLI that writes one-hour caches can make a bucket read `over` with nobody else on the key. A second user spending under the tolerance in a bucket where a run was active is invisible: the default is $0.05 per bucket, buckets an hour wide. `SINCE` and `UNTIL` are local time, the buckets are UTC, and the provider's figures arrive within about five minutes. It has run against a fake server and this tool's own ledger, not against the live Admin API or a real export (Status).

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

**Marked `unconfirmed` in `config.toml`** (the pages read do not confirm them; options that need them are refused, naming the field): `effort_flag`, `resume_flag` (the CLI resumes with the subcommand `exec resume`, which is not wired). **Assumptions, listed in every dry run and summary:** that `input_tokens` includes `cached_input_tokens` (the sample numbers suggest it; if wrong, the true cost is understated); that `output_tokens` includes reasoning tokens; whether `usage` is per turn or cumulative (SIwithin sums `turn.completed` events); whether the CLI's own sandbox starts inside SIwithin's profile (the default is `--sandbox workspace-write`, and `read-only` with `--readonly`; if it refuses to start, set `args_write` in `config.toml` knowingly); where the binary installs (SIwithin allows the folder of the one it finds on `PATH`); the format of `--version`. `--read` folders are not announced to this CLI, because its `--add-dir` grants writes.

## What it does not do

- **Linux and Windows.** No fence there, so SIwithin refuses. On the roadmap, not started.
- **A hosted team ledger.** The ledger is a file on one machine.
- **More CLIs.** Two are built in; a third can be declared in `config.toml` if it speaks one of the two output formats (`claude-stream-json`, `codex-jsonl`). Other formats need code.
- **The proxy for the second adapter.** It serves the first adapter only; the Codex adapter keeps `auth = "env"`, the key in the run's environment, and with it no network wall: its runs need `--network open`.
- **A config directory per run.** A run can read the transcripts of the adapter's earlier runs, briefs included (SECURITY.md, "Known gaps").
- **Also not done.** Mid-turn budget enforcement for CLIs that report usage late, a ceiling check at the proxy, resume and effort for the second adapter, a verified run of the second adapter against a live CLI, and the wall under any adapter but the first (above).
- **Streamed output tokens for the first adapter's stop.** The CLI's stream reports a response's real output count only in its final result; its SDK documentation says a partial-messages option streams the running count, and SIwithin does not use it. The streamed stop is therefore a lower bound on output-heavy runs (see "The ledger"); with the proxy on, the proxy's total is what the ledger books. On the 48-turn run of 18 October 2026 the stream's running total was $0.0156 against the proxy's $0.0272 (Status).
- **The live reconcile.** `--reconcile` (Reconcile) sets the provider's usage report against the ledger, and has run against a fake server and this tool's own ledger only: not the live Admin API, whose key individual accounts are not offered, and not a real Console export, whose header was not seen. It does not ask the report for speed, geography or context window, so spend there is priced as standard and understated.

## Configuration

Copy `config.example.toml` to `~/.config/siwithin/config.toml`. Every option is there with a one-line comment, and every value is the built-in default, so keep only what you change; `[auth]` holds `key_command`, `upstream`, `upstream_timeout` and `paths`; `[fence] network` picks the run's network, `proxy`, `report` or `open`; `[reconcile]` holds `admin_key_command`, `api_key_ids` and `tolerance`, and `[prices] cache_write_1h_factor` the one-hour cache write's ratio (Reconcile). `--home <folder>` moves all of SIwithin's paths (`config.toml`, `cap`, `ledger.md`, `lock`, `runs/`, the per-CLI config directories) in one go.

## Status

Version 0.5.0, released 19 October 2026: `--reconcile` (Reconcile); `--version` prints `siwithin 0.5.0`, the smoke test passes 291 checks with fake CLIs and a fake usage server, and the red fake pass 92 (CHANGELOG). Reconcile was built the evening of the 0.4.0 release from the Usage and Cost API's documentation, read that day, and tested in the suite against a fake server on the loopback: paging, the arithmetic of every token kind worked by hand, the three verdicts, the admin key in no file and no output, the CSV way, the watch, and that it starts no sandbox and writes no ledger line. It ran once against this tool's own ledger, with a usage export written by hand in the header the suite assumes: the 48-turn run of 18 October (below), its tokens from its proxy log placed in their hour, reconciled `ok` at $0.0272 on both sides; a row an hour later with no run active read `unaccounted $0.0600 in 1 buckets`, exit 1. Not run: the live Admin API, which individual accounts are not offered, and a real export, so the Console export's header is taken from the API's field names, and a header the tool cannot match is printed and refused. The API's report also groups by speed, inference geography and context window, each of which changes the price; the tool does not ask for them, and spend there is priced as standard (Reconcile, "What it does not see").

0.4.0, released 18 October 2026: the network wall (The fence) and `STOLEN-KEYS.md`; `--version` prints `siwithin 0.4.0`, the smoke test passes 266 checks with fake CLIs and the red fake pass 92 (CHANGELOG). The wall was built on 15 October after a read of the Claude Code documentation's table of the hosts the CLI opens and a probe of `sandbox-exec`'s socket rules on this machine. Run live the same morning, three runs on the red home with Claude Code 2.1.296 and Haiku, each four turns and under a minute: a survey in `report` mode of an ordinary task counted 12 sockets, 7 to port 443 besides 2 to the proxy's port, 2 to the resolver and one unix socket the CLI binds in the run's temp root; the same task under the wall finished in the same four turns at the same cost with 8 refusals, the resolver's 7 and the bind, and no attempt on 443 since no name resolved; the `net-out` brief held, its program's connection to a public address refused with errno 1 and its two lookups with errno 8, the proxy reachable (`tests/red/scorecard-2026-10-15-3.md`). Comparing the runner's figures with the kernel's log found two faults in its reading, fixed the same morning (CHANGELOG); the figures here are the corrected reader's over the log. On 18 October 2026 one run of 48 turns and 3.1 minutes on the red home with Claude Code 2.1.302 and Haiku, a thirty-file writing task with two network attempts half way, a fetch by the CLI's own tool and a Python request: both failed in the run's own record, the tool unable to verify the domain and the request with errno 8 from the resolver; 44 requests went through the proxy, all `/v1/messages`, $0.0272 true, equal to the CLI's own figure; the kernel's report counted 51 refusals, 50 to the resolver's socket (49 the CLI's, one the Python program's) and the CLI's one unix-socket bind, none to port 443, `late 0`; `outlived 0`; the receipt verified with `--expect`; the kernel's lines had left the unified log five minutes after the run, so the runner's reads at the run's end are the record. Two of the run's shell commands were refused by the CLI's own permission layer, compound commands with substitutions, not by the fence. Not known yet: another adapter under the wall (the second adapter runs with `--network open`), and whether a CLI that waits on a socket at start would hang under it; this CLI binds one unix socket in its temp root, is refused, and finishes. `STOLEN-KEYS.md`, what a stolen key costs, written after the OpenCode Console breach of 17 October 2026: where a key is taken from, what each layer did, and what this tool does and does not do about it.

0.3.0, released 15 October 2026: the key proxy and the kill walk, `--verify --expect`, finite money, the proxy's path allowlist, four more programs on `deny_exec`, and two red briefs for the key and the kill; `--version` prints `siwithin 0.3.0` and the smoke test passes 244 checks with fake CLIs. The proxy and the walk ran live in the red passes of 14 and 15 October 2026 on Claude Code 2.1.296 with Haiku (Tests): the five earlier walls held, the budget stop fired by design, the `env-key` brief found no key value in the run's environment or its ancestors', and the `outlive` brief's detached program was found and killed, `outlived 1`, after a first pass showed the walk killing it and not counting it (CHANGELOG). Of the four gaps a read of the whole code as a stranger found on 14 October, three are closed and one, the transcripts, is open, and 0.3.0 names its own; [SECURITY.md](SECURITY.md), "Known gaps", has each with what replaced it. After the release, the same day: the proxy's 402 at the budget was seen live in the `second-client` brief, released in 0.4.0 (CHANGELOG), the proxy refusing a second client's request and the CLI's own next one once its total reached the budget, forwarding nothing after, the run killed; and a survey run of 8 turns on the red home called `/v1/messages` only, so no other path has been seen live.

Earlier: 0.2.1, 14 October 2026, printed a budget under a cent with four decimals; 0.2.0, 14 October 2026, the receipt, live on one run that day; four live runs on 13 October 2026 on Claude Code 2.1.296, the CLI's budget flag firing in two of them, a run past the cap refused before launch, and no write refused by the fence or seen outside the run folders. On a new machine, still run `python3 siwithin.py --dir <a scratch folder> --dry-run < /dev/null`, then a trivial brief, and read `stderr.txt` before you rely on it.

## Tests

```
python3 tests/smoke.py
```

Runs with a temporary home and no CLI installed: dry runs for each adapter, the fence profile's lines, forbidden folders, the cap arithmetic, the config reader, and (on macOS) whole runs against fake CLIs with the sandbox program replaced by a shim, so the streaming, kill, ledger and summary code is exercised, including a fake that streams usage past a budget (the run, its child process and its ledger line must be killed for it) and one that stays under; the receipts, written for each booked run and not for a refused one, chained, and `--verify` passing on the home and failing on a changed result, a changed cost, a replaced hash, a changed run folder, a bare line after the first receipt and a wrong `--expect`; the proxy's checks against a fake upstream and a fake CLI on loopback; and the kill walk against fakes that detach a process, scrub their environment, hold the pipe open or leave an orphan; and the network wall's three modes in dry runs and whole runs, with the kernel's log replaced by a shim that returns canned report lines; and, since 0.5.0, a fake usage server on the loopback with `--reconcile` run against it and fake homes: paging, the arithmetic, the verdicts, the admin key's leak check over every file and output, the CSV way and the watch. 291 checks. The fence itself is not tested there.

The red briefs, `tests/red/`, test the fence. Nine ordinary-sounding tasks each cross one wall: a write to the home directory outside the run's folder, a write to `/tmp`, the start of a program on `deny_exec`, a write to SIwithin's own ledger, a task long enough to pass a small budget, a search for the key in the run's environment and its ancestors', a program detached into a session of its own that must not outlive the kill, a second client of the API, started by the task, whose spend no stream shows and the proxy must count and stop at the budget, and a program that opens sockets outside the key proxy's port (a public address, the resolver, an https fetch), which the network wall must refuse (`net-out`, not yet run live). `python3 tests/red/run.py --fake` proves the scorer on planted run folders and runs nothing live. `--live` runs each brief through `siwithin.py` with Haiku against a red home, scores the run folders, runs the key-leak detector and `--verify`, and writes a scorecard whose last column is each run's receipt hash; `--live --only <id>` re-runs one. The six scorecards of 14 and 15 October 2026 are in the folder: four walls held in each of the first three passes, the budget stop by design in the third at $0.0002 true against a budget of $0.0001 (the `$0.00` in that kill status is what 0.2.1 fixed); in the fourth pass the five held again and `env-key` held, while `outlive` showed the walk killing the detached program and not counting it, which that night's fix closed; the fifth pass re-ran `outlive` alone and it held, `outlived 1`; the sixth ran `second-client` alone and it held: the proxy priced the second client's three requests, refused its fourth with 402 once the total passed the $0.005 budget, refused the CLI's own next request 38 ms later, and the run was killed with nothing forwarded, at $0.0056 true. 25 receipts verified: the 24 red runs cost $0.0770 together on the red home's ledger, and a survey run of 8 turns there, for the paths a real CLI calls, $0.0057; it called `/v1/messages` only. [tests/red/README.md](tests/red/README.md) has the walls, the verdicts, and the finding that a model shown its remaining budget does not cross it.

## Renaming

Change `NAME` at the top of `siwithin.py`. The default home, the messages, the ledger header and the lock text follow.

## License

Apache License 2.0. See [LICENSE](LICENSE). Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

Copyright 2026 metahumansworld. Licensed under the Apache License, Version 2.0; see LICENSE.
