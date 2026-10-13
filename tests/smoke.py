#!/usr/bin/env python3
"""Smoke test: python3 tests/smoke.py. A temporary home, no agent CLI installed, nothing outside the temporary folder is touched.

Part 1 runs siwithin.py --dry-run as a subprocess for each built-in adapter and asserts the command, the fence profile's deny and allow lines,
the refusal of forbidden folders, the cap arithmetic and the adapters' refusals. Part 2 checks the pieces: the TOML reader, the example config,
the money, the profile builder. Part 3 (macOS) drives a whole run in-process against fake CLIs with the sandbox program replaced by a shim that
only drops its profile argument: it tests what the tool does around the CLI (streaming, kills, ledger, summary), not the fence itself."""
import copy, importlib.util, io, json, os, re, shlex, shutil, stat, subprocess, sys, tempfile, textwrap, time

sys.dont_write_bytecode = True  # importing siwithin.py must not leave a __pycache__ in the project
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec =importlib.util.spec_from_file_location("siwithin_under_test", os.path.join(ROOT, "siwithin.py"))
siwithin = importlib.util.module_from_spec(spec); spec.loader.exec_module(siwithin)

failures, count = [], 0


def check(cond, what):
    global count
    count += 1
    if not cond: failures.append(what); print(f"FAIL {what}")


def group(name): print(f"-- {name}")


TMP = os.path.realpath(tempfile.mkdtemp(prefix="siwithin-smoke-"))
HOME = os.path.join(TMP, "home"); os.makedirs(HOME)
FH = os.path.join(HOME, ".config", siwithin.NAME); os.makedirs(FH)
PROJ = os.path.join(HOME, "work", "proj"); os.makedirs(PROJ)
READ = os.path.join(HOME, "work", "ref"); os.makedirs(READ)
ENV = {"HOME": HOME, "PATH": "/usr/bin:/bin", "USER": "tester", "LANG": "C"}  # no CLI on this PATH
DARWIN = sys.platform == "darwin"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f: f.write(text)


def tool_cli(args, brief="a brief\n", env=None):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "siwithin.py")] + args, input=brief, capture_output=True, text=True, env=env or ENV, timeout=60)
    return r.returncode, r.stdout, r.stderr


def section(out, head, nxt):
    return out.split(f"== {head} ==\n", 1)[1].split(f"== {nxt} ==", 1)[0] if f"== {head} ==" in out else ""


def tokens(out):
    return shlex.split(section(out, "command", "fence profile").split("\n", 1)[0])


def after(toks, flag): return toks[toks.index(flag) + 1]


try:
    # ---------------------------------------------------------------- part 1: dry runs
    write(os.path.join(FH, "cap"), "10\n")
    write(os.path.join(FH, "ledger.md"), f"# {siwithin.NAME} ledger\n"
          "2026-10-01 09:00 | a | /x | claude sonnet - | 3 turns | 1.0 min | cli $4.2500 | true $4.2500 | in 1k out 1k | runs/a | done\n"
          "2026-10-02 09:00 | b | /x | claude sonnet - | 3 turns | 1.0 min | cli $2.2500 | true $2.2500 | in 1k out 1k | runs/b | done\n")
    good_rc = 0 if DARWIN else 1  # elsewhere the dry run prints everything and still reports the refusal

    group("claude dry run")
    rc, out, err = tool_cli(["--dir", PROJ, "--read", READ, "--dry-run"])  # the default budget of 5 is over what the ledger and cap leave: exit 1, everything still printed
    check(rc == 1, f"claude dry run exit {rc}, stderr {err!r}")
    t = tokens(out)
    check(t[0] == siwithin.SANDBOX_EXEC and t[1] == "-f" and t[2].endswith("/fence.sb") and t[3] == "claude" and t[4] == "-p", f"command starts with the fence and the CLI: {t[:5]}")
    check(after(t, "--max-turns") == "40" and after(t, "--max-budget-usd") == "5", "turn limit 40 and budget flag 5 (factor 1)")
    check(t.count("--add-dir") == 2 and PROJ in t and READ in t, "both folders announced with --add-dir")
    check("stream-json" == after(t, "--output-format") and "--verbose" in t, "stream-json output")
    check(after(t, "--tools").endswith("Bash") and "Bash(git commit:*)" in t and "Bash(git push:*)" in t and t.index("--disallowedTools") < t.index("Bash(git push:*)"), "tools, local git allowed, git push denied")
    check("--model" not in t and "--effort" not in t, "no model or effort unless asked")
    prof = section(out, "fence profile", "config checks")
    lines = [x for x in prof.split("\n") if x]
    check(f'(deny file-read* (subpath "{HOME}"))' in lines, "profile refuses reads in the home")
    check(any(x.startswith(f'(deny file-write* (subpath "{HOME}")') for x in lines), "profile refuses writes in the home")
    check(f'(allow file-read* (subpath "{PROJ}"))' in lines and f'(allow file-write* (subpath "{PROJ}"))' in lines, "first folder readable and writable")
    check(f'(allow file-read* (subpath "{READ}"))' in lines and f'(allow file-write* (subpath "{READ}"))' not in lines, "--read folder readable only")
    check(f'(deny file-read* (subpath "{FH}"))' in lines and f'(deny file-write* (subpath "{FH}"))' in lines, "the tool's own home refused")
    check(f'(allow file-read* (subpath "{FH}/claude-config"))' in lines and f'(allow file-write* (subpath "{FH}/claude-config"))' in lines, "the CLI's config directory allowed back")
    check(lines.index(f'(deny file-read* (subpath "{HOME}"))') < lines.index(f'(allow file-read* (subpath "{PROJ}"))') < lines.index(f'(deny file-read* (subpath "{FH}"))'),
          "later rules win: home deny, then folders, then the tool's home deny")
    check(any(f'(literal "{HOME}/.zshrc")' in x and x.startswith("(allow file-read*") for x in lines) and any(f'"{HOME}/Library/Keychains"' in x for x in lines), "rc files and keychain allowed back")
    check(any(x.startswith("(deny process-exec") and '"/usr/bin/osascript"' in x for x in lines), "osascript refused")
    NO_FILTER = r"\((allow|deny) (file-[a-z-]+\*?|process-exec)\)"  # a rule with nothing listed would apply to everything
    check(".ssh" not in prof and not any(re.fullmatch(NO_FILTER, x) for x in lines), "no .ssh allowed and no rule without a filter")
    check("/Users/" not in prof.replace(HOME, ""), "no path but the temporary home in the profile")
    bud = section(out, "budget", "\0")
    check("$6.50 true over 2 runs" in bud and "$6.50 + $5.00 = $11.50 of $10.00" in bud and "REFUSED" in bud, "cap arithmetic printed: 6.50 + 5.00 passes 10.00")
    rc, out, err = tool_cli(["--dir", PROJ, "--dry-run"])
    check(rc == 1 and "ledger true total $6.50 + budget $5.00 passes the cap $10.00" in out, "over the cap: exit 1 and the reason in the checks")
    rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "3.5"])
    check(rc == good_rc and "within the cap $10.00" in out and "worst case after this run: $6.50 + $3.50 = $10.00 of $10.00" in out, "6.50 + 3.50 = 10.00 is within a cap of 10 (the edge)")
    rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "3.5", "--model", "haiku"])
    t = tokens(out)
    check(after(t, "--model") == "claude-haiku-5-5" and after(t, "--max-budget-usd") == "3.5", "alias resolved; haiku budget 3.5 x factor 1 = 3.5 in the CLI's units")
    check("0.1 / 0.125 / 0.01 / 0.5" in out and "(factor 1 between the CLI's units and true dollars)" in out, "rates and factor shown")
    bud = section(out, "budget", "\0")
    N = siwithin.NAME
    rc, out, err = tool_cli(["--version"])
    check(rc == 0 and out.strip() == "siwithin 0.1.2", f"--version prints siwithin 0.1.2: {out.strip()!r}")
    check("enforced twice:" in bud and f"1. by the CLI: --max-budget-usd 3.5 (factor 1 between" in bud, "dry run, enforcement 1: the CLI's flag with its factor")
    check(f"2. by {N}, from the stream" in bud and "once per message id" in bud and 'killed: budget $3.50 reached at $<true> true' in bud and "output tokens are a placeholder" in bud,
          "dry run, enforcement 2: the streamed true-cost stop, its message and its limit")
    FH3 = os.path.join(TMP, "f40"); os.makedirs(FH3)
    write(os.path.join(FH3, "cap"), "100"); write(os.path.join(FH3, "config.toml"), '[factors]\n"claude-haiku-5-5" = 40\n')
    rc, out, err = tool_cli(["--home", FH3, "--dir", PROJ, "--dry-run", "--budget", "3.5", "--model", "haiku"])
    check(after(tokens(out), "--max-budget-usd") == "140" and "(factor 40 between" in out and "2. by " + N + ", from the stream" in out, "a factor set in [factors] is honoured by the flag, and the streamed stop is still printed")
    rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "3.5", "--model", "not-priced"])
    check(rc == good_rc and "the streamed stop cannot price it" in out and "no price for not-priced in [prices]: this stop cannot count it, and only the CLI's flag stops the run" in out,
          "claude with a model that has no price: allowed, and the dry run says only the flag stops it")
    rc, out, err = tool_cli(["--dir", PROJ, "--readonly", "--read", READ, "--dry-run", "--budget", "1"])
    t = tokens(out); prof = section(out, "fence profile", "config checks")
    check(after(t, "--tools") == "Read,Grep,Glob,WebSearch,WebFetch" and "Edit" not in t, "readonly: no editing tools, no shell")
    check(f'(allow file-read* (subpath "{PROJ}"))' in prof and f'(allow file-write* (subpath "{PROJ}"))' not in prof, "readonly: nothing writable")
    check(tool_cli(["--dir", PROJ, "--readonly", "--out", "x.md", "--dry-run"])[0] == 1, "--out with --readonly refused")
    os.rename(os.path.join(FH, "cap"), os.path.join(FH, "cap.off"))
    rc, out, err = tool_cli(["--dir", PROJ, "--dry-run"])
    check(rc == 1 and "no readable cap" in out and "echo 20 >" in out, "no cap file: refused with the way to make one")
    os.rename(os.path.join(FH, "cap.off"), os.path.join(FH, "cap"))
    rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--out", "../escape.md"])
    check(rc == 1 and "outside the run's folder" in err, "--out outside --dir refused")

    group("forbidden folders")
    write(os.path.join(FH, "config.toml"), f'[never]\nfolders = ["{HOME}/work/secret"]\n')
    for rel in (".ssh", ".config/x", "Library/Application Support", ".claude", ".codex", "work/secret/deep", f".config/{siwithin.NAME}/runs"): os.makedirs(os.path.join(HOME, rel), exist_ok=True)
    for label, folder in (("home root", HOME), ("~/.ssh", f"{HOME}/.ssh"), ("~/.config", f"{HOME}/.config/x"), ("~/Library", f"{HOME}/Library/Application Support"), ("~/.claude", f"{HOME}/.claude"),
                          ("~/.codex", f"{HOME}/.codex"), ("[never] folder", f"{HOME}/work/secret/deep"), ("the tool's home", f"{FH}/runs"), ("parent of the home", os.path.dirname(HOME)),
                          ("case variant", f"{HOME}/.SSH"), ("a folder holding a [never] one", f"{HOME}/work")):
        for flag in ("--dir", "--read"):
            args = ["--dir", folder, "--dry-run"] if flag == "--dir" else ["--dir", PROJ, "--read", folder, "--dry-run"]
            rc, out, err = tool_cli(args)
            if label == "case variant" and not os.path.isdir(folder): continue  # a case-sensitive volume: the folder does not exist
            check(rc == 1 and err.startswith("refused:") and "== command ==" not in out, f"{flag} {label} refused ({err.strip()[:90]})")
    rc, out, err = tool_cli(["--dir", os.path.join(HOME, "nope"), "--dry-run"])
    check(rc == 1 and "is not a folder" in err, "a missing folder is refused")
    os.remove(os.path.join(FH, "config.toml"))

    group("codex dry run")
    FH2 = os.path.join(TMP, "elsewhere"); os.makedirs(FH2)
    write(os.path.join(FH2, "cap"), "50"); write(os.path.join(FH2, "config.toml"), '[prices]\n"made-up-1" = [1.0, 1.0, 0.5, 4.0]\n')
    base = ["--home", FH2, "--adapter", "codex", "--dir", PROJ, "--dry-run"]
    rc, out, err = tool_cli(base + ["--model", "gpt-5.3-codex"])
    check(rc == 1 and "--soft-budget" in err and "== command ==" not in out, "codex: refused without --soft-budget, with the reason")
    rc, out, err = tool_cli(base + ["--soft-budget"])
    check(rc == 1 and "--model is needed" in err, "codex: refused without --model (priced by model id)")
    rc, out, err = tool_cli(base + ["--soft-budget", "--model", "not-priced"])
    check(rc == 1 and "no price for not-priced" in err, "codex: refused for a model with no price")
    rc, out, err = tool_cli(base + ["--soft-budget", "--model", "gpt-5.3-codex", "--turns", "3"])
    check(rc == 1 and "no way to set a turn limit" in err, "codex: --turns refused, the CLI has none")
    rc, out, err = tool_cli(base + ["--soft-budget", "--model", "gpt-5.3-codex", "--effort", "high"])
    check(rc == 1 and "effort_flag is unconfirmed" in err, "codex: --effort refused, the flag is unconfirmed")
    rc, out, err = tool_cli(base + ["--soft-budget", "--model", "gpt-5.3-codex", "--resume", "abc"])
    check(rc == 1 and "resume_flag is unconfirmed" in err, "codex: --resume refused, the flag is unconfirmed")
    rc, out, err = tool_cli(base + ["--soft-budget", "--model", "gpt-5.3-codex", "--require-api-key"])
    check(rc == 1 and "cannot be checked" in err, "codex: --require-api-key refused, no way to check")
    rc, out, err = tool_cli(base + ["--soft-budget", "--model", "gpt-5.3-codex", "--read", READ, "--budget", "2"])
    check(rc == good_rc, f"codex dry run exit {rc}, stderr {err!r}")
    t = tokens(out)
    check(t[3] == "codex" and t[4:7] == ["exec", "--json", "--skip-git-repo-check"], f"codex: exec --json --skip-git-repo-check ({t[3:8]})")
    check(after(t, "--model") == "gpt-5.3-codex" and after(t, "--cd") == PROJ and after(t, "--sandbox") == "workspace-write", "codex: model, --cd, workspace-write")
    check(after(t, "--output-last-message").endswith("/last-message.txt") and t[-1] == "-", "codex: final message file, prompt from stdin by -")
    check(not {"--max-budget-usd", "--max-turns", "--add-dir", "--effort"} & set(t), "codex: no budget flag, no turn flag, no --add-dir (it grants writes)")
    prof = section(out, "fence profile", "config checks")
    check(f'(allow file-write* (literal "{os.path.dirname(after(t, "-f"))}/last-message.txt"))' in prof or "last-message.txt" in prof, "codex: the one file it writes in the run's folder is allowed")
    check(f'(deny file-read* (subpath "{FH2}"))' in prof and f'(allow file-read* (subpath "{FH2}/codex-config"))' in prof, "codex: --home moves the tool's home and the config directory with it")
    check(not any('/runs/' in x and '/tmp")' in x for x in prof.split("\n")), "codex: no temp root in the run's folder (it has no variable for one)")
    check("checked by siwithin when each turn ends" in out and "1.75 / 1.75 / 0.175 / 14.0" in out and "fields marked unconfirmed" in out and "not run against" not in out and "built from documentation" in out, "codex: budget mode, rates and the unconfirmed fields shown")
    check("--read folders" in out or "not told about --read" in out, "codex: --read folder not announced to the CLI, said so")
    rc, out, err = tool_cli(["--home", FH2, "--adapter", "codex", "--dir", PROJ, "--dry-run", "--soft-budget", "--model", "made-up-1"])
    check(rc == good_rc and "1.0 / 1.0 / 0.5 / 4.0" in out, "codex: a price row from config.toml is merged in")
    rc, out, err = tool_cli(["--home", FH2, "--adapter", "nope", "--dir", PROJ, "--dry-run"])
    check(rc == 1 and "unknown adapter" in err, "unknown adapter refused")
    if not DARWIN:
        check("refuses to run on" in tool_cli(["--dir", PROJ, "--dry-run"])[1], "non-macOS: the refusal and the roadmap are printed")

    # ---------------------------------------------------------------- part 2: pieces
    group("pieces")
    example = open(os.path.join(ROOT, "config.example.toml"), encoding="utf-8").read()
    parsed = siwithin.parse_toml_mini(example)
    check(parsed == siwithin.DEFAULT_CONFIG, "config.example.toml read by the built-in reader equals the built-in defaults")
    if siwithin.tomllib: check(siwithin.tomllib.loads(example) == parsed, "tomllib and the built-in reader agree on the example")
    sample = textwrap.dedent('''\
        # comment
        a = 1_000        # trailing comment
        b = -2.5
        c = true
        d = 2026-10-13
        [t."x.y"]
        k = ["a", 'b\\n', "c\\u00e9\\n",   # inside
             3, ]
        inline = { p = 1, q = "r" }
        dotted.key = "v"
        [t.u]
        e = ""
        ''')
    got = siwithin.parse_toml_mini(sample)
    check(got == {"a": 1000, "b": -2.5, "c": True, "d": "2026-10-13", "t": {"x.y": {"k": ["a", "b\\n", "cé\n", 3], "inline": {"p": 1, "q": "r"}, "dotted": {"key": "v"}}, "u": {"e": ""}}}, f"built-in reader on edge cases: {got}")
    for bad in ('a = """x"""', "[[x]]\n", "a = \n", "a = 1 b = 2", 'a = "x', "a = 1\na = 2"):
        try: siwithin.parse_toml_mini(bad); check(False, f"built-in reader should reject {bad!r}")
        except ValueError: check(True, "")
    u = {"in": 1_000_000, "cache_write": 0, "cache_read": 2_000_000, "out": 100_000, "searches": 3}
    tt, notes = siwithin.true_total({"claude-sonnet-5-5": u}, {}, siwithin.DEFAULT_CONFIG["prices"], {})
    check(abs(tt - (2.0 + 0.2 + 1.0 + 0.03)) < 1e-9 and not notes, f"true cost at published rates: {tt}")
    tt, notes = siwithin.true_total({"mystery": u}, {"mystery": 8.0}, siwithin.DEFAULT_CONFIG["prices"], {"mystery": 4})
    check(tt == 2.0 and "no price for mystery" in notes[0], "an unpriced model falls back to the CLI's figure over its factor, and says so")
    big = {"in": 10_000_000, "cache_write": 0, "cache_read": 0, "out": 0, "searches": 0}  # haiku 5.5: $1.00 true
    fn = lambda cli, f: siwithin.factor_notes({"claude-haiku-5-5": big}, {"claude-haiku-5-5": cli}, siwithin.DEFAULT_CONFIG["prices"], {"claude-haiku-5-5": f}, "9.9.9")
    check(siwithin.DEFAULT_CONFIG["factors"]["claude-haiku-5-5"] == 1, "the default factor for the small model is 1")
    check(fn(40.0, 40) == [] and fn(10.0, 40) == [] and fn(160.0, 40) == [] and len(fn(9.0, 40)) == 1 and len(fn(161.0, 40)) == 1 and len(fn(1.0, 40)) == 1,
          "stale-factor check, factor 40: warns below a quarter of it (a stale 40 on a CLI that prices truly) and above four times it, and not inside")
    check(fn(1.0, 1) == [] and fn(0.25, 1) == [] and fn(4.0, 1) == [] and len(fn(0.2, 1)) == 1 and len(fn(4.5, 1)) == 1 and len(fn(40.0, 1)) == 1 and "ratio of 40.00" in fn(40.0, 1)[0],
          "stale-factor check, factor 1: a CLI that prices the model at another model's rates (ratio 40) is caught")
    shape = {"type": "assistant", "message": {"model": "claude-sonnet-5-5", "usage": {"input_tokens": 2, "cache_creation_input_tokens": 9920, "cache_read_input_tokens": 0,
             "cache_creation": {"ephemeral_5m_input_tokens": 9920, "ephemeral_1h_input_tokens": 0}, "output_tokens": 8, "service_tier": "standard", "inference_geo": "global"}}}
    st = siwithin.new_state(None)
    for _ in range(3): siwithin.feed_claude(st, shape, {})  # the real shape: three identical events, no message id
    check(st["usage"] == {"claude-sonnet-5-5": {"in": 2, "cache_write": 9920, "cache_read": 0, "out": 8, "searches": 0}} and st["assistant_events"] == 3 and st["usage_events"] == 3,
          f"stream usage, the real shape: three identical events with no id count once: {st['usage']}")
    siwithin.feed_claude(st, {"type": "assistant", "message": {"model": "claude-sonnet-5-5", "usage": {"input_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 9920, "output_tokens": 30}}}, {})
    check(st["usage"]["claude-sonnet-5-5"] == {"in": 3, "cache_write": 9920, "cache_read": 9920, "out": 38, "searches": 0}, "stream usage: an event that differs is a new response")
    st = siwithin.new_state("claude-sonnet-5-5")
    for mid, cw in (("m1", 100), ("m1", 100), ("m2", 100)): siwithin.feed_claude(st, {"type": "assistant", "message": {"id": mid, "usage": {"cache_creation_input_tokens": cw, "output_tokens": 8}}}, {})
    check(st["usage"] == {"claude-sonnet-5-5": {"in": 0, "cache_write": 200, "cache_read": 0, "out": 16, "searches": 0}}, "stream usage: with ids, each id counts once, and the run's model stands in when an event names none")
    siwithin.feed_claude(st, {"type": "assistant", "message": {"content": []}}, {}); siwithin.feed_claude(st, {"type": "assistant", "message": {"model": "<synthetic>", "usage": {"input_tokens": 0, "output_tokens": 0}}}, {})
    check(st["assistant_events"] == 5 and st["usage_events"] == 4 and list(st["usage"]) == ["claude-sonnet-5-5"], "stream usage: an event without usage is counted as such, and an all-zero message adds no model")
    siwithin.feed_claude(st, {"type": "result", "subtype": "success", "result": "x", "num_turns": 1, "total_cost_usd": 0.1, "modelUsage": {"claude-haiku-5-5": {"inputTokens": 7, "costUSD": 0.1}}}, {})
    check(st["complete"] and list(st["usage"]) == ["claude-haiku-5-5"] and st["usage"]["claude-haiku-5-5"]["in"] == 7, "the result event replaces what streamed")
    check(siwithin.forbidden_reason("/a/B/c", "/a", [("/a/b", "x")]) is not None and siwithin.forbidden_reason("/a/bb", "/a", [("/a/b", "x")]) is None and siwithin.forbidden_reason("/", "/a", []) is not None, "forbidden_reason: case-insensitive, whole path parts, ancestors of the home")
    c = siwithin.SimpleNamespace(home="/h", folders=["/h/p"], readonly=False, siwithin_home="/h/.config/f", config_dir="/h/.config/f/c", run="/h/.config/f/runs/r", tmp=False, last_message=False,
                              fence=dict(siwithin.DEFAULT_CONFIG["fence"], write_home=[], deny_exec=[], rc_files=[]), read_extra=[], write_extra=[])
    pl = [x for x in siwithin.fence_profile(c).split("\n") if x and not x.startswith(";")]
    check(not any(re.fullmatch(NO_FILTER, x) for x in pl) and not any("process-exec" in x for x in pl), "empty lists leave no rule behind (an empty allow would allow everything)")
    check('(allow file-read-metadata (literal "/h/.config")' in " ".join(pl) or '(literal "/h/.config")' in " ".join(pl), "folders above allowed ones get metadata only")
    write(os.path.join(TMP, "l.md"), "# header with true $9 in it\n2026-10-01 09:00 | a | /x | y | z | true $1.5000 | done\nnot a line | true $7\n2026-10-02 09:00 | b | true $0.2500 (ceiling)\n")
    check(siwithin.ledger_total(os.path.join(TMP, "l.md")) == (1.75, 2), "ledger total counts dated lines only")

    # ---------------------------------------------------------------- part 3: whole runs against fake CLIs
    if DARWIN:
        group("whole runs, fake CLIs")
        E = os.path.join(TMP, "e2e"); EH = os.path.join(E, "home"); EF = os.path.join(EH, ".config", siwithin.NAME); BIN = os.path.join(E, "bin"); ED = os.path.join(EH, "proj")
        for p in (EF, BIN, ED): os.makedirs(p)
        write(os.path.join(EF, "cap"), "100")
        write(os.path.join(EF, "config.toml"), '[adapters.claude]\nenv_pass = ["ANTHROPIC_API_KEY", "FAKE_AUTH"]   # the fake CLI is told how to answer through a listed variable\n')
        shim =os.path.join(BIN, "sandbox-shim")
        write(shim, f"#!{sys.executable}\nimport os, sys\nassert sys.argv[1] == '-f' and os.path.isfile(sys.argv[2])\nos.execv(sys.argv[3], sys.argv[3:])\n")
        write(os.path.join(BIN, "claude"), f"""#!{sys.executable}
import json, os, subprocess, sys, time
a = sys.argv[1:]
if a == ["--version"]: print("2.1.296 (fake)"); sys.exit(0)
if a == ["auth", "status"]: print(json.dumps({{"loggedIn": True, "authMethod": os.environ.get("FAKE_AUTH", "api_key")}})); sys.exit(0)
brief = sys.stdin.read(); sys.stderr.write("env names: " + ",".join(sorted(os.environ)) + "\\n"); sys.stderr.flush()
src = "none" if "MODE:wrongkey" in brief else "ANTHROPIC_API_KEY"
def ev(o): print(json.dumps(o), flush=True)
ev({{"type": "system", "subtype": "init", "apiKeySource": src, "session_id": "sess-1"}})
if "MODE:hang" in brief: time.sleep(60)
def msg(mid, model="claude-sonnet-5-5", **u):  # one assistant event: the shape of seed/sample-events.md, with an id, and output_tokens a placeholder of 8
    usage = {{"input_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 8, "service_tier": "standard"}}; usage.update(u)
    ev({{"type": "assistant", "message": {{"id": mid, "model": model, "usage": usage, "content": []}}}})
if "MODE:overbudget" in brief:  # $0.25 (the response is sent twice, and counts once), then $0.30 more: $0.5502 in all, past a budget of $0.50, then the CLI keeps going
    open("child.pid", "w").write(str(subprocess.Popen(["sleep", "60"]).pid))  # a tool process of the CLI's, in the same process group
    msg("msg_A", cache_creation_input_tokens=100000); msg("msg_A", cache_creation_input_tokens=100000)
    msg("msg_B", input_tokens=100000, cache_read_input_tokens=1000000)
    time.sleep(60)
elif "MODE:nousage" in brief: ev({{"type": "assistant", "message": {{"content": []}}}})
elif "MODE:unpriced" in brief: msg("msg_U", model="claude-mystery-1", input_tokens=50000000)
else: msg("msg_A", cache_creation_input_tokens=100000); msg("msg_A", cache_creation_input_tokens=100000); msg("msg_B", input_tokens=100000)  # $0.4502, under a budget of $0.50
text = "All good. DONE-MARKER" + (" TODO" if "MODE:todo" in brief else "")
ev({{"type": "result", "subtype": "success", "is_error": False, "num_turns": 3, "result": text, "total_cost_usd": 0.3, "session_id": "sess-1",
    "modelUsage": {{"claude-sonnet-5-5": {{"inputTokens": 100000, "outputTokens": 10000, "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0, "webSearchRequests": 0, "costUSD": 0.3}}}},
    "permission_denials": [{{"tool_name": "Bash", "tool_input": {{"command": "git push"}}}}]}})
""")
        write(os.path.join(BIN, "codex"), f"""#!{sys.executable}
import json, sys, time
a = sys.argv[1:]
if a == ["--version"]: print("codex-cli 0.0.0-fake"); sys.exit(0)
brief = sys.stdin.read()
def ev(o): print(json.dumps(o), flush=True)
ev({{"type": "thread.started", "thread_id": "thr-1"}})
ev({{"type": "turn.started"}})
ev({{"type": "item.completed", "item": {{"id": "i1", "type": "agent_message", "text": "codex says DONE-MARKER"}}}})
open(a[a.index("--output-last-message") + 1], "w").write("codex says DONE-MARKER")
ev({{"type": "turn.completed", "usage": {{"input_tokens": 1000000, "cached_input_tokens": 500000, "output_tokens": 100000, "reasoning_output_tokens": 0}}}})
if "MODE:twoturns" in brief: ev({{"type": "turn.started"}}); time.sleep(60)
""")
        for p in ("sandbox-shim", "claude", "codex"): os.chmod(os.path.join(BIN, p), 0o755)
        saved_env, saved_stdin, saved_sb = dict(os.environ), sys.stdin, siwithin.SANDBOX_EXEC
        SECRET = "sk-test-NOT-A-REAL-KEY-12345"

        def whole(args, brief="do the thing\n", extra_env=None):
            os.environ.clear(); os.environ.update({"HOME": EH, "PATH": BIN + ":/usr/bin:/bin", "USER": "t", "ANTHROPIC_API_KEY": SECRET, "CODEX_API_KEY": SECRET, "UNLISTED_VARIABLE": "x", **(extra_env or {})})
            sys.stdin = io.StringIO(brief); siwithin.SANDBOX_EXEC = shim
            o, e = io.StringIO(), io.StringIO(); so, se = sys.stdout, sys.stderr; sys.stdout, sys.stderr = o, e
            try: rc = siwithin.main(args)
            finally:
                sys.stdout, sys.stderr = so, se; os.environ.clear(); os.environ.update(saved_env); sys.stdin = saved_stdin; siwithin.SANDBOX_EXEC = saved_sb
            return rc, o.getvalue(), e.getvalue()

        def last_run():
            runs = sorted(os.listdir(os.path.join(EF, "runs")), key=lambda n: os.stat(os.path.join(EF, "runs", n)).st_mtime_ns)  # by time: "-run-10" sorts before "-run-9" by name
            r = os.path.join(EF, "runs", runs[-1])
            return r, json.load(open(os.path.join(r, "summary.json")))

        def ledger(): return open(os.path.join(EF, "ledger.md")).read().strip().split("\n")

        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--name", "first run!", "--out", "out/result.txt", "--done", "DONE-MARKER", "--absent", "TODO"])
        r, s = last_run()
        check(rc == 0 and s["status"] == "done", f"claude run done: rc {rc}, {s.get('status')}, {err}")
        check(abs(s["true_cost"] - 0.30) < 1e-9 and s["cli_cost"] == 0.3 and s["turns"] == 3 and s["tokens_in"] == 100000 and s["tokens_out"] == 10000, f"cost, turns, tokens in the summary: {s}")
        check(s["key_source"] == "ANTHROPIC_API_KEY" and s["session_id"] == "sess-1" and s["cli_version"] == "2.1.296" and not s["notes"], f"key source, session, CLI version, no notes: {s['notes']}")
        check(s["contract"] == {"done": {"text": "DONE-MARKER", "found": True}, "absent": {"text": "TODO", "found": False}}, "--done found, --absent not found")
        check(open(os.path.join(ED, "out", "result.txt")).read() == "All good. DONE-MARKER" and open(os.path.join(r, "result.md")).read() == "All good. DONE-MARKER", "--out written inside --dir, result.md written")
        check(all(os.path.exists(os.path.join(r, f)) for f in ("brief.md", "command.txt", "events.jsonl", "stderr.txt", "result.md", "summary.json", "fence.sb")) and r.endswith("-first-run"), "the run folder holds the record")
        check(len(open(os.path.join(r, "events.jsonl")).read().strip().split("\n")) == 5, "events.jsonl holds the CLI's events")
        check(s["stream_cost"] == 0.4502, f"the summary holds what the stream priced: {s['stream_cost']}")
        L = ledger()
        check(len(L) == 2 and L[0].startswith("# ") and re.search(r"\| first-run \| .*\| claude sonnet - \| 3 turns \| .* min \| cli \$0\.3000 \| true \$0\.3000 \| in 100k out 10k \| runs/.*-first-run \| done$", L[1]), f"one ledger line: {L[-1]}")
        check("true $0.30 of cap $100" in out.replace("0.3000", "0.30") or "ledger true total $0.30 of cap $100" in out, "summary line carries the ledger total and the cap")
        check("paid by ANTHROPIC_API_KEY" in out and "denials 1" in out and "denied: Bash" in out and out.startswith(f"{siwithin.NAME} done | claude sonnet -"), "summary line in the seed's format")
        every = "".join(open(os.path.join(r, f)).read() for f in os.listdir(r) if os.path.isfile(os.path.join(r, f))) + open(os.path.join(EF, "ledger.md")).read() + out + err
        check(SECRET not in every, "the key's value is nowhere in the run folder, the ledger or the output")
        names = re.search(r"env names: (.*)", open(os.path.join(r, "stderr.txt")).read()).group(1).split(",")
        check("UNLISTED_VARIABLE" not in names and "ANTHROPIC_API_KEY" in names and "CLAUDE_CONFIG_DIR" in names and "CLAUDE_CODE_TMPDIR" in names, f"the run's environment is the short list: {names}")
        check(os.path.isdir(os.path.join(r, "tmp")) and os.path.isdir(os.path.join(EF, "claude-config")), "run temp root and the config directory made")

        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--done", "NOT-THERE", "--out", "second.txt"])
        r, s = last_run()
        check(rc == 1 and s["status"] == "finished, contract unmet: done text missing" and not os.path.exists(os.path.join(ED, "second.txt")) and "MISSING" in out and "not written" in " ".join(s["notes"]), f"contract unmet: {s['status']}")
        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--absent", "TODO"], brief="MODE:todo")
        check(rc == 1 and "absent text found" in last_run()[1]["status"] and "FOUND" in out, "--absent text found makes the run not done")
        rc, out, err = whole(["--dir", ED], brief="MODE:wrongkey")
        r, s = last_run()
        check(rc == 1 and s["status"].startswith("killed: key source is 'none'") and s["true_cost"] == 0 and not s["true_cost_is_ceiling"], f"wrong key source killed at init, nothing billed: {s['status']}")
        rc, out, err = whole(["--dir", ED], extra_env={"FAKE_AUTH": "claude.ai"})
        check(rc == 1 and "might be billed to a login" in err and "--no-require-api-key" in err, "a login in the CLI's auth: refused before launch, with the reason")
        check(json.load(open(os.path.join(last_run()[0], "summary.json")))["status"].startswith("refused:"), "the refusal is recorded in the run folder")
        n_lines = len(ledger())
        rc, out, err = whole(["--dir", ED, "--no-require-api-key"], extra_env={"FAKE_AUTH": "claude.ai"})
        check(rc == 0 and len(ledger()) == n_lines + 1, "--no-require-api-key accepts a login")
        t0 = time.time(); rc, out, err = whole(["--dir", ED, "--timeout", "2", "--budget", "4"], brief="MODE:hang")
        r, s = last_run()
        check(rc == 1 and s["status"] == "killed: timeout 2s" and time.time() - t0 < 30, f"timer kills a hung run: {s['status']}")
        check(s["true_cost_is_ceiling"] and s["true_cost"] == 4.0 and "(ceiling, usage unreported)" in ledger()[-1] and "true $4.0000" in ledger()[-1], "killed with usage unreported: the ledger holds the budget as a ceiling, and says so")
        # the streamed true-cost stop, claude adapter. Sonnet is priced 2.0 / 2.5 / 0.10 / 10.0 per million tokens; the fake streams usage that passes a budget of $0.50
        def _alive(pid):
            try: os.kill(pid, 0); return True
            except ProcessLookupError: return False
            except PermissionError: return True
        t0 = time.time(); rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--budget", "0.5", "--timeout", "30"], brief="MODE:overbudget")
        r, s = last_run(); KILLED = "killed: budget $0.50 reached at $0.5502 true"
        check(rc == 1 and s["status"] == KILLED and time.time() - t0 < 20, f"streamed usage past the budget: the run is killed, with the exact reason ({s['status']}, {err})")
        check(ledger()[-1].endswith(f"| {KILLED}") and "true $0.5502" in ledger()[-1] and "cli $-" in ledger()[-1], f"the ledger line says it was killed for the budget: {ledger()[-1]}")
        check(out.startswith(f"{siwithin.NAME} {KILLED} | claude sonnet -") and abs(s["true_cost"] - 0.5502) < 1e-9 and not s["true_cost_is_ceiling"] and s["stream_cost"] == 0.5502, f"the summary line and summary.json: {out[:90]}")
        check(any("killed before the CLI's result" in n and "placeholder" in n for n in s["notes"]), f"the summary notes say the figure is what streamed: {s['notes']}")
        cmd_line = shlex.split(open(os.path.join(r, "command.txt")).read().split("\n", 1)[0])
        check(after(cmd_line, "--max-budget-usd") == "0.5", "the CLI's flag is still given, as a second stop")
        pid = int(open(os.path.join(ED, "child.pid")).read()); alive = _alive(pid)
        for _ in range(30):
            if not alive: break
            time.sleep(0.1); alive = _alive(pid)
        check(not alive, "the kill reached the whole process group: the CLI's own child process is gone")
        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--budget", "0.5"])
        r, s = last_run()
        check(rc == 0 and s["status"] == "done" and s["stream_cost"] == 0.4502 and "killed" not in ledger()[-1] and not s["notes"], f"streamed usage under the budget: not killed ({s['status']}, stream ${s['stream_cost']}, {s['notes']})")
        check(abs(s["true_cost"] - 0.30) < 1e-9, "a run that finishes is booked at the result's usage, not at the streamed figure")
        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--budget", "0.5"], brief="MODE:nousage")
        r, s = last_run()
        check(rc == 0 and s["status"] == "done" and s["stream_cost"] is None and any("no usage on any of its assistant events" in n and "kept by the CLI's flag" in n and "alone" in n for n in s["notes"]), f"no usage in the stream: the flag alone, and the notes say so: {s['notes']}")
        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--budget", "0.5"], brief="MODE:unpriced")
        r, s = last_run()
        check(rc == 0 and s["status"] == "done" and any("could not count claude-mystery-1" in n and "approximate" in n for n in s["notes"]), f"a model with no price: not counted by the streamed stop, and the notes say so: {s['notes']}")
        before = len(ledger())
        lk = siwithin.acquire_lock(os.path.join(EF, "lock"))
        rc, out, err = whole(["--dir", ED])
        lk.close()
        check(rc == 1 and "another run is live" in err and len(ledger()) == before, "a second run is refused while the lock is held")
        write(os.path.join(EF, "cap"), "1"); before = len(ledger())
        rc, out, err = whole(["--dir", ED])
        check(rc == 1 and "passes the cap $1.00" in err and len(ledger()) == before, "a real run over the cap is refused and leaves no line")
        write(os.path.join(EF, "cap"), "100")
        rc, out, err = whole(["--dir", os.path.join(EH, ".ssh")])
        check(rc == 1 and "refused" in err, "forbidden folder refused in a real run too")

        rc, out, err = whole(["--adapter", "codex", "--dir", ED, "--model", "gpt-5.3-codex", "--soft-budget", "--done", "DONE-MARKER"])
        r, s = last_run()
        check(rc == 0 and s["status"] == "done" and abs(s["true_cost"] - 2.3625) < 1e-9 and s["cli_cost"] is None and s["turns"] == 1 and s["session_id"] == "thr-1", f"codex run: {s}")
        check(s["tokens_in"] == 1000000 and s["tokens_out"] == 100000 and open(os.path.join(r, "result.md")).read() == "codex says DONE-MARKER", "codex: tokens, result from the final-message file")
        check(any("assumptions unconfirmed" in n for n in s["notes"]) and any("when each turn ends" in n for n in s["notes"]) and any("0.0.0-fake" in n for n in s["notes"]), f"codex: unconfirmed assumptions, soft budget and unmeasured version in the notes: {s['notes']}")
        check("cli $-" in ledger()[-1] and "true $2.3625" in ledger()[-1] and "paid by -" in out, "codex: no CLI cost, shown as cli $-")
        env_names = open(os.path.join(r, "command.txt")).read()
        check("CODEX_HOME" in env_names and "CODEX_API_KEY" in env_names and SECRET not in env_names, "codex: environment names in command.txt, no values")
        rc, out, err = whole(["--adapter", "codex", "--dir", ED, "--model", "gpt-5.3-codex", "--soft-budget", "--budget", "1"])
        r, s = last_run()
        check(rc == 0 and s["status"] == "done" and any(n.startswith("over budget") for n in s["notes"]), f"codex single turn over a soft budget: finished, reported over budget ({s['status']})")
        t0 = time.time(); rc, out, err = whole(["--adapter", "codex", "--dir", ED, "--model", "gpt-5.3-codex", "--soft-budget", "--budget", "1"], brief="MODE:twoturns")
        r, s = last_run()
        check(rc == 1 and s["status"].startswith("killed: budget $1.00 reached") and not s["true_cost_is_ceiling"] and time.time() - t0 < 30, f"codex starts a second turn past the budget: killed ({s['status']})")
        check(siwithin.ledger_total(os.path.join(EF, "ledger.md"))[1] == len(ledger()) - 1, "every run is one ledger line")
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print(f"\n{count - len(failures)} of {count} checks passed" + ("" if DARWIN else " (macOS-only checks skipped)"))
if failures:
    print("FAILED: " + "; ".join(failures)); sys.exit(1)
print("PASS")
