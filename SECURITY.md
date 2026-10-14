# SIwithin security

This file says what the tool is built to stop, what it does not stop, and how to report a problem. Read it before you trust the fence with anything you cannot afford to lose.

## Threat model

The tool runs an agent CLI unattended. The agent is **not trusted**: it can be wrong, it can be steered by text it reads (a web page, a file in the folder, a dependency's README), and it runs commands. The person running the tool is trusted and chose the CLI, the folders and the budget. The tool and the CLI's binary are trusted code.

What the tool protects, in order:

1. The user's files outside the folders a run was given (keys, tokens, shell history, other projects, browser profiles, the tool's own ledger and the briefs of other runs).
2. The user's money: what a run, and all runs together, can spend.
3. The truth of the record: the ledger, each run's summary and, from 0.2.0, each run's receipt, a manifest of the hashes of the files the run wrote, chained through the ledger and checked by `--verify` (the README's receipt section says what it proves and what it does not).

What it does not protect against: a malicious CLI binary, a malicious `config.toml`, a hostile local user, or an attacker who already controls the account running the tool. In 0.2.1 it also does not keep the key from the run, nor a process the run detaches from the budget kill, nor earlier runs' transcripts from a run: see "Known gaps" below.

## What the fence stops (macOS, `sandbox-exec`)

The profile is generated per run, from a template, with the home folder derived at run time (`--dry-run` prints it; the run folder keeps it as `fence.sb`).

- **Reads and writes in the home folder are refused whole.** Only these are allowed back: the run's folders (readable; the first also writable unless `--readonly`), the CLI's binary, the CLI's own config directory for the run, caches, logs and keychain files under `~/Library`, Python user packages, the shell's rc files, and git's config.
- **Writes are refused** in `/private/tmp`, `/tmp`, `/opt`, `/usr/local`, `/Applications`, `/Library` and `/Volumes` (the list is `[fence] deny_write`).
- **The tool's own home is refused** to the run (config, cap, ledger, other runs' briefs and events), except the run's own temp folder, the CLI's config directory and the one file a CLI is told to write its final message to.
- **Some programs may not be started**: `open`, `screencapture`, `osascript`, `say`, `afplay` (`[fence] deny_exec`).
- **The tool refuses to give a run** the home root or any folder holding it, `~/.ssh`, `~/.config`, `~/Library`, each adapter's own config directory, the tool's home, or a `[never]` folder, as `--dir` or `--read`. This matters because the fence enforces only what the launcher asks: a folder allowed back would otherwise open what is inside it. Paths are resolved through symlinks and compared without regard to case.
- **The run's environment is a short list** of variables and the names you add; the rest of the shell's environment (organisation, account and token variables of a desktop session, for example) is not inherited.
- **One run at a time**, by a lock held for the run's length.
- **The money**: the budget is passed to the CLI where it has a flag, and also kept by the runner from the usage the CLI streams, where it streams any (a wrong factor between the CLI's units and true dollars then cannot lift the budget); where the CLI has no flag the runner keeps it alone. The cap is checked under the lock before every run. A timer kills every run. A run stopped by the timer or an interrupt before it reported its usage is booked at its budget.
- **The key**: the tool never reads, parses, stores, prints or logs a key. It copies the variables you name in `env_pass` into the child's environment, and records their names only; the child, and every command the run starts, can read them ("Known gaps"). With `--require-api-key` it asks the CLI how it is signed in before launch and checks the key source in the CLI's first event, and kills the run if either says the bill would go to a login.

## What the fence does not stop

- **The network.** A run can fetch and send anything the machine can reach. The profile does not restrict sockets. A run can send the contents of every folder it was given to any host. Do not give a run a folder whose contents must not leave the machine, and keep the CLI's web tools off if that matters (`args_write` in the adapter).
- **The rest of the disk.** The home is refused; other users' folders, `/etc`, `/Users/Shared` and anything outside the home and the listed write roots can still be read, and writes outside the home are blocked only in the listed roots.
- **What the run writes into its own folder.** Scripts, git hooks, build files, `.envrc`, package manifests. If you run, commit with hooks, or build there later, outside the fence, you run what it wrote. Review before you use it.
- **Files the fence allows back.** The shell's rc files are readable: a key exported in `~/.zshrc` is visible to the run, so keep keys out of rc files. The keychain files under `~/Library/Keychains` are readable, and since 0.2.0 not writable (their items are protected by the system, not by this tool). Caches and logs under `~/Library` are shared with every program you run.
- **The CLI's own sandbox, cloud or remote tools.** If a CLI runs commands in its own sandbox, a cloud task or a remote machine, those run where the fence is not. Nested sandboxes may refuse to start on macOS; v0.1 has not tested the second built-in adapter's own sandbox inside the fence (see the README).
- **A budget that cannot be kept mid-turn.** For a CLI that reports usage only when a turn ends, one long turn can pass the budget before the runner sees it. The tool refuses such a CLI unless `--soft-budget` is given, and the ledger records what was spent.
- **A streamed stop that lags on output.** The first built-in adapter's stream reports each response's output tokens as a placeholder; the real count comes only in the final result. The runner's stop therefore counts input and cache tokens fully and output tokens barely, so it never comes early and on a run heavy in output it comes after the true budget. The CLI's own flag is the other stop. A run killed by the runner's stop is booked at what streamed, which understates it by the output not yet reported, and its notes say so. A model with no entry in `[prices]` is not counted by the runner's stop at all; only the CLI's flag limits it.
- **Prices that are wrong or old.** The true cost is computed at the rates in `[prices]`; a run that uses a higher tier than the listed one, or a rate that has changed, is understated. The CLI's own figure is shown beside it.
- **The prompt itself.** If a brief is passed as a command-line argument (`brief = "arg"` in an adapter), it is visible in the process list. The built-in adapters use stdin.
- **Apple's `sandbox-exec`.** It is deprecated by Apple, undocumented in places, and as strong as the profile and the kernel's enforcement. A bug in either is a way out. The profile text is short on purpose: read it.
- **Other platforms.** There is no fence on Linux or Windows in v0.1, so the tool refuses to run there rather than pretend.

## Not verified in this release

- The profile was built from constructs the launcher it grew from already used. It compiled and ran live on 13 October 2026, four runs on Claude Code 2.1.296, and once more on 14 October for the receipt (README, Status): the fence refused no write in them, and what the CLI wrote in the paths the fence allows it, its config directory and the caches, was not listed. The runner's own budget kill, the second enforcement, ran live once, on 14 October 2026 in the third red pass (`tests/red/scorecard-2026-10-14-3.md`): a run under a budget of $0.0001 was killed at $0.0002 true. Run `python3 siwithin.py --dir <a scratch folder> --dry-run < /dev/null`, then a real run of a trivial brief, and read `stderr.txt` before you rely on it.
- The second built-in adapter was built from documentation and not run against a live CLI (see the README).
- `tests/smoke.py` drives whole runs against fake CLIs with the sandbox program replaced by a shim: it tests what the tool does around the CLI, the receipt included, not the fence.

## Known gaps, found 14 October 2026

A read of the whole code as a stranger, on 14 October 2026, against the tree at commit 481401e, found these. Each is from reading, not from a live run, unless it says so. The fix named for each is planned, not built, as of this commit.

- **The run can read the key, and spend with it unseen.** With the environment-variable path, `ANTHROPIC_API_KEY` is in the CLI's environment, and every command the run starts inherits it: the environment is built at launch from the names in `env_pass`. With the helper path, the helper and the `settings.json` naming it are readable and runnable inside the fence, because the CLI runs the helper there. The network is open, so the key can be sent anywhere; and a call to the API made by the run's own commands, or a second CLI started from the run, passes through nothing the runner prices, so the ledger stays green. Until it is fixed: a key made for SIwithin alone, in a workspace with a spend limit set in the provider's console. The fix, planned for 0.3.0: the runner keeps the key and talks to the API for the run through a loopback proxy that meters every request; the run gets a per-run token worth nothing elsewhere.
- **A process the run detaches outlives the budget kill.** The kill is one `killpg` of the CLI's process group. A child started in a new session is outside it and keeps running after the kill, the timer and the ledger line, with the key and the network. The fix: kill by ancestry, every process descended from the CLI, and hold the lock until none is left; the proxy above stops its spending.
- **Earlier runs' transcripts are readable.** The adapter's config directory is one directory under SIwithin's home, shared by the adapter's runs and readable whole, so the CLI finds its settings. The CLI keeps its transcripts there, so a run can read what every earlier run read and wrote, in every folder, briefs included. The README's "other runs' briefs are refused" is true of the briefs in SIwithin's home and false of their copies in the transcripts. The fix: a config directory per run, seeded from the adapter's.
- **The verifier passes a cut or stripped ledger.** `--verify` checks each line that carries a receipt; a line without one is counted and passed, and nothing refers to lines removed from the end. So a ledger with its last lines deleted, or its receipt fields stripped, verifies. The fix: a bare line after the first receipt fails, and `--verify --expect <hash>` checks the last receipt against a hash kept elsewhere.
- **Smaller.** `--budget nan` is accepted and disables both stops. The streamed stop counts the four token fields of assistant events, not web searches or the CLI's side-query model, which appear only in the final result. If the runner itself dies (a closed terminal, a crash), nothing is booked and the cap does not see that run. `$TMPDIR` is the user's own, and `/private/var/tmp`, `/var/folders` and `/Users/Shared` are writable. The run folder's own `.claude/` settings are loaded by the CLI on the next run there (`--setting-sources user,project`), so a run can leave settings for the next one in that folder, and a cloned repository can bring its own. `deny_exec` is five path matches; a copy of the binary, `launchctl` or `cron` are untested ways around it. The memory carve-out's pattern is case-sensitive on a case-insensitive volume. The smoke and red tests pass on Python 3.9.6, below the README's stated floor.

## Reporting a problem

Report a fence bypass, a way for a run to exceed its budget or the cap, a way to get the tool to read or print a key, a false entry in the ledger, or a receipt or chain that still verifies after a change **privately**, not in a public issue.

- Write to **siwithin@metahumans.world**.
- Or use the repository's private vulnerability reporting on GitHub (the Security tab, "Report a vulnerability").
- Include the macOS version, the output of `siwithin.py --version`, the `fence.sb` and `command.txt` from the run folder (remove anything private), the run's `receipt.json` if there is one, and the steps to reproduce.

No response time is promised yet. Reports are welcome, and a fix will be credited if the reporter wants it.
