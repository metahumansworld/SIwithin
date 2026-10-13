# SIwithin security

This file says what the tool is built to stop, what it does not stop, and how to report a problem. Read it before you trust the fence with anything you cannot afford to lose.

## Threat model

The tool runs an agent CLI unattended. The agent is **not trusted**: it can be wrong, it can be steered by text it reads (a web page, a file in the folder, a dependency's README), and it runs commands. The person running the tool is trusted and chose the CLI, the folders and the budget. The tool and the CLI's binary are trusted code.

What the tool protects, in order:

1. The user's files outside the folders a run was given (keys, tokens, shell history, other projects, browser profiles, the tool's own ledger and the briefs of other runs).
2. The user's money: what a run, and all runs together, can spend.
3. The truth of the record: the ledger and each run's summary.

What it does not protect against: a malicious CLI binary, a malicious `config.toml`, a hostile local user, or an attacker who already controls the account running the tool.

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
- **The key**: the tool never reads, parses, stores, prints or logs a key. It copies the variables you name in `env_pass` into the child's environment, and records their names only. With `--require-api-key` it asks the CLI how it is signed in before launch and checks the key source in the CLI's first event, and kills the run if either says the bill would go to a login.

## What the fence does not stop

- **The network.** A run can fetch and send anything the machine can reach. The profile does not restrict sockets. A run can send the contents of every folder it was given to any host. Do not give a run a folder whose contents must not leave the machine, and keep the CLI's web tools off if that matters (`args_write` in the adapter).
- **The rest of the disk.** The home is refused; other users' folders, `/etc`, `/Users/Shared` and anything outside the home and the listed write roots can still be read, and writes outside the home are blocked only in the listed roots.
- **What the run writes into its own folder.** Scripts, git hooks, build files, `.envrc`, package manifests. If you run, commit with hooks, or build there later, outside the fence, you run what it wrote. Review before you use it.
- **Files the fence allows back.** The shell's rc files are readable: a key exported in `~/.zshrc` is visible to the run, so keep keys out of rc files. The keychain files under `~/Library/Keychains` are readable and writable (their items are protected by the system, not by this tool). Caches and logs under `~/Library` are shared with every program you run.
- **The CLI's own sandbox, cloud or remote tools.** If a CLI runs commands in its own sandbox, a cloud task or a remote machine, those run where the fence is not. Nested sandboxes may refuse to start on macOS; v0.1 has not tested the second built-in adapter's own sandbox inside the fence (see the README).
- **A budget that cannot be kept mid-turn.** For a CLI that reports usage only when a turn ends, one long turn can pass the budget before the runner sees it. The tool refuses such a CLI unless `--soft-budget` is given, and the ledger records what was spent.
- **A streamed stop that lags on output.** The first built-in adapter's stream reports each response's output tokens as a placeholder; the real count comes only in the final result. The runner's stop therefore counts input and cache tokens fully and output tokens barely, so it never comes early and on a run heavy in output it comes after the true budget. The CLI's own flag is the other stop. A run killed by the runner's stop is booked at what streamed, which understates it by the output not yet reported, and its notes say so. A model with no entry in `[prices]` is not counted by the runner's stop at all; only the CLI's flag limits it.
- **Prices that are wrong or old.** The true cost is computed at the rates in `[prices]`; a run that uses a higher tier than the listed one, or a rate that has changed, is understated. The CLI's own figure is shown beside it.
- **The prompt itself.** If a brief is passed as a command-line argument (`brief = "arg"` in an adapter), it is visible in the process list. The built-in adapters use stdin.
- **Apple's `sandbox-exec`.** It is deprecated by Apple, undocumented in places, and as strong as the profile and the kernel's enforcement. A bug in either is a way out. The profile text is short on purpose: read it.
- **Other platforms.** There is no fence on Linux or Windows in v0.1, so the tool refuses to run there rather than pretend.

## Not verified in this release

- The profile was built from constructs the launcher it grew from already used, but it was not compiled by `sandbox-exec` while building v0.1. Run `python3 siwithin.py --dir <a scratch folder> --dry-run < /dev/null`, then a real run of a trivial brief, and read `stderr.txt` before you rely on it.
- The second built-in adapter was built from documentation and not run against a live CLI (see the README).
- `tests/smoke.py` drives whole runs against fake CLIs with the sandbox program replaced by a shim: it tests what the tool does around the CLI, not the fence.

## Reporting a problem

Report a fence bypass, a way for a run to exceed its budget or the cap, a way to get the tool to read or print a key, or a false entry in the ledger **privately**, not in a public issue.

- Use the private vulnerability reporting of the repository that hosts this project (the Security tab, "Report a vulnerability"), once the project is hosted.
- Include the macOS version, the output of `siwithin.py --version`, the `fence.sb` and `command.txt` from the run folder (remove anything private), and the steps to reproduce.
- Or write to **people@metahumans.world**.

No response time is promised in v0.1. Reports are welcome, and a fix will be credited if the reporter wants it.
