#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SIwithin: run an agent CLI headless on a brief, inside a folder fence, under a dollar budget and a cap, leaving one record per run.

Usage: python3 siwithin.py --dir <folder> [--adapter claude|codex] [--model M] [--effort E] [--budget 5] [--turns 40] [--timeout 2700]
       [--read <folder>]... [--readonly] [--name <slug>] [--out <file, inside --dir>] [--resume <session id>]
       [--done "<text>"] [--absent "<text>"] [--soft-budget] [--require-api-key | --no-require-api-key]
       [--home <folder>] [--dry-run] < brief
The brief comes on stdin. The tool's home (default ~/.config/siwithin) holds config.toml, cap, ledger.md, lock and runs/; each run's folder under
runs/ gets the brief, the command, the fence profile, the CLI's events and stderr, result.md and summary.json. macOS only in v0.1.

Findings from the launcher this grew out of, each made on a real CLI and kept because they explain a choice below:
- Billing: with a login present in the CLI's config directory, the CLI signs with the login although its init event names an API key source.
  So each run gets a config directory of its own (no login in it), the CLI's auth status is asked before launch, and the init event is checked.
  The CLI's bare mode avoids the login too, but it is the CLI's simple mode, three tools only, whatever --tools names; it is not used.
- Environment: a run gets a short list of variables and nothing else. A desktop app's session shell carries organisation, account and
  auth-refresh variables, and a run that inherited them was billed to the login's organisation while the same run from an empty environment
  was paid by the key.
- The fence refuses the whole home and allows folders back. A fence that listed folders to refuse left the rest of the home readable: settings,
  transcripts, shell histories, browser profiles. The fence also enforces only what the launcher asks, so the launcher refuses the folders no run is given.
- The CLI's per-user temp root, where every session keeps its scratch files, is moved into the run's folder so /private/tmp can be refused whole.
- One run at a time, by a lock held for the run's length: a second launch from any session is refused while one runs.
- Git is held to local subcommands, and the tools that launch further runs are dropped, so nothing leaves the machine and a run cannot start runs.
- A CLI can price a model at another model's rates: its budget is then in units that are not dollars. [factors] holds the ratio and a check warns when it goes stale.
  A factor that is wrong lifts the CLI's flag by that much and nothing else stops the run, so where the CLI streams usage the budget is also kept here, in true dollars.
- A CLI's assistant events carry the usage of one API response each, and one response can arrive as several events with the same message id and the same usage:
  count each id once. Per-event output tokens are a placeholder (the count when the response began); the real output arrives only in the result event.
"""
from __future__ import annotations

import argparse, copy, datetime, json, os, re, shlex, shutil, signal, subprocess, sys, threading
from types import SimpleNamespace

try: import tomllib  # Python 3.11+; the reader below covers 3.10
except ImportError: tomllib = None

NAME = "siwithin"  # the one constant to change when the tool is renamed: default home, messages, ledger header, lock text
VERSION = "0.1.2"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"  # absolute, so a PATH entry cannot stand in for the fence; a module constant, not an environment switch
UNCONFIRMED = "unconfirmed"  # an adapter field holding this is a stub: any option that needs it is refused, naming the field
ROADMAP = "README.md, 'What v0.1 does not do'"
PRICE_STALE_DAYS = 90


class Refused(Exception):
    pass


# ---- config: defaults, a TOML reader for Python 3.10, merge ---------------------------------------------------------------------

CLAUDE_BASH = ("ls", "mkdir", "cp", "cat", "date", "pwd", "echo", "printf", "head", "tail", "wc", "find", "test", "touch", "python3", "grep", "sort", "cut", "du", "stat", "sed")
CLAUDE_GIT = ("init", "status", "add", "commit", "log", "diff", "show", "rev-parse", "branch", "checkout", "switch", "restore", "stash", "mv", "rm", "ls-files", "blame", "tag")
CLAUDE_GIT_DENY = ("push", "pull", "fetch", "remote", "clone", "submodule", "config")
CLAUDE_DENY = ["Agent", "Skill", "NotebookEdit", "ListAgents", "SendMessage", "Artifact", "Workflow", "AskUserQuestion", "ScheduleWakeup", "SendUserFile", "Monitor",
               "ToolSearch", "TaskStop", "EnterPlanMode", "ExitPlanMode", "EnterWorktree", "ExitWorktree"] + [f"Bash(git {c}:*)" for c in CLAUDE_GIT_DENY]
CLAUDE_TOOLS = ["Read", "Grep", "Glob", "Edit", "Write", "WebSearch", "WebFetch"]
CLAUDE_READ_TOOLS = ["Read", "Grep", "Glob", "WebSearch", "WebFetch"]

DEFAULT_CONFIG = {
    "defaults": {"adapter": "claude", "budget": 5.0, "turns": 40, "timeout": 2700},
    "never": {"folders": []},
    "fence": {
        "read_home": ["Library/Caches", "Library/Logs", "Library/Keychains", "Library/Python", ".gitconfig", ".config/git"],
        "write_home": ["Library/Caches", "Library/Logs", "Library/Keychains"],
        "rc_files": [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout", ".bash_profile", ".bash_login", ".bashrc", ".profile"],
        "deny_write": ["/private/tmp", "/tmp", "/opt", "/usr/local", "/Applications", "/Library", "/Volumes"],
        "deny_exec": ["/usr/bin/open", "/usr/sbin/screencapture", "/usr/bin/osascript", "/usr/bin/say", "/usr/bin/afplay"],
    },
    "env": {"pass": ["HOME", "PATH", "USER", "TMPDIR", "LANG", "SHELL", "TERM"]},
    # Dollars per million tokens: input, cache write, cache read, output. Read from the pages named in source, on read_on.
    "prices": {
        "read_on": "2026-10-13",
        "source": "platform.claude.com/docs/en/about-claude/pricing; developers.openai.com/api/docs/pricing",
        "web_search": 0.01,
        "claude-haiku-5-5": [0.10, 0.125, 0.01, 0.50],
        "claude-sonnet-5-5": [2.0, 2.5, 0.10, 10.0],
        "claude-opus-5-5": [4.0, 5.0, 0.20, 20.0],
        "claude-haiku-4-5-20251001": [1.0, 1.25, 0.10, 5.0],
        "gpt-5.3-codex": [1.75, 1.75, 0.175, 14.0],
        "gpt-6.1-sol": [2.0, 2.0, 0.10, 10.0],
    },
    # CLI budget units per true dollar. CLI 2.1.284 priced this model at Opus rates and needed 40 here; CLI 2.1.296 prices it truly, so 1.
    # On 2.1.284 a user sets 40 under [factors] in config.toml.
    "factors": {"claude-haiku-5-5": 1},
    "adapters": {
        "claude": {
            "bin": "claude", "own_dir": "~/.claude", "config_dir": "{fence_home}/claude-config", "config_dir_env": "CLAUDE_CONFIG_DIR",
            "tmp_env": "CLAUDE_CODE_TMPDIR", "read_home": [".local/bin", ".local/share/claude"], "write_home": [], "env_pass": ["ANTHROPIC_API_KEY"],
            "output": "claude-stream-json", "usage_at": "message", "input_includes_cached": False,
            "brief": "stdin", "brief_arg": "", "cwd_flag": "", "model_flag": "--model", "effort_flag": "--effort", "effort_env": "CLAUDE_CODE_EFFORT_LEVEL",
            "turns_flag": "--max-turns", "budget_flag": "--max-budget-usd", "add_dir_flag": "--add-dir", "resume_flag": "--resume", "last_message_flag": "",
            "args": ["-p", "--setting-sources", "user,project", "--strict-mcp-config", "--permission-mode", "acceptEdits", "--output-format", "stream-json", "--verbose"],
            "args_write": ["--tools", ",".join(CLAUDE_TOOLS + ["Bash"]), "--allowedTools", *CLAUDE_TOOLS, *[f"Bash({c}:*)" for c in CLAUDE_BASH],
                           *[f"Bash(git {c}:*)" for c in CLAUDE_GIT], "--disallowedTools", *CLAUDE_DENY],
            "args_readonly": ["--tools", ",".join(CLAUDE_READ_TOOLS), "--allowedTools", *CLAUDE_READ_TOOLS, "--disallowedTools", *CLAUDE_DENY],
            "extra_args": [], "version_args": ["--version"], "auth_status_args": ["auth", "status"],
            "auth_methods_ok": ["api_key", "api_key_helper"], "key_sources_ok": ["apiKeyHelper", "ANTHROPIC_API_KEY"], "require_api_key": True,
            "measured": ["2.1.284", "2.1.296"], "unconfirmed": [],
            "aliases": {"haiku": "claude-haiku-5-5", "sonnet": "claude-sonnet-5-5", "opus": "claude-opus-5-5"},
        },
        "codex": {
            "bin": "codex", "own_dir": "~/.codex", "config_dir": "{fence_home}/codex-config", "config_dir_env": "CODEX_HOME",
            "tmp_env": "", "read_home": [], "write_home": [], "env_pass": ["CODEX_API_KEY"],
            "output": "codex-jsonl", "usage_at": "turn", "input_includes_cached": True,
            "brief": "stdin", "brief_arg": "-", "cwd_flag": "--cd", "model_flag": "--model", "effort_flag": UNCONFIRMED, "effort_env": "",
            "turns_flag": "", "budget_flag": "", "add_dir_flag": "", "resume_flag": UNCONFIRMED, "last_message_flag": "--output-last-message",
            "args": ["exec", "--json", "--skip-git-repo-check"],
            "args_write": ["--sandbox", "workspace-write"], "args_readonly": ["--sandbox", "read-only"],
            "extra_args": [], "version_args": ["--version"], "auth_status_args": [],
            "auth_methods_ok": [], "key_sources_ok": [], "require_api_key": False,
            "measured": [], "unconfirmed": ["input_includes_cached", "output_includes_reasoning", "usage_is_per_turn", "sandbox_runs_inside_fence", "install_location", "version_output"],
            "aliases": {},
        },
    },
}
BLANK_ADAPTER = {k: ("" if isinstance(v, str) else [] if isinstance(v, list) else {} if isinstance(v, dict) else False)
                 for k, v in DEFAULT_CONFIG["adapters"]["claude"].items()}


class TomlError(ValueError):
    pass


TOML_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


def parse_toml_mini(text):
    """The subset of TOML the config uses, for Python 3.10: tables, dotted and quoted keys, strings, numbers, booleans, arrays, inline tables."""
    s, n, i = text, len(text), 0
    root = cur = {}

    def err(msg):
        raise TomlError(f"line {s.count(chr(10), 0, i) + 1}: {msg}")

    def skip(newlines=False):
        nonlocal i
        while i < n:
            if s[i] in " \t" or (newlines and s[i] in "\r\n"): i += 1
            elif s[i] == "#":
                while i < n and s[i] != "\n": i += 1
            else: break

    def string():
        nonlocal i
        q = s[i]
        if s.startswith(q * 3, i): err("multi-line strings are not supported by the built-in reader")
        i += 1; out = []
        while i < n and s[i] != q:
            if s[i] == "\n": err("unterminated string")
            if q == '"' and s[i] == "\\":
                i += 1; c = s[i:i + 1]
                if c in ("u", "U"):
                    k = 4 if c == "u" else 8; out.append(chr(int(s[i + 1:i + 1 + k], 16))); i += k
                elif c in TOML_ESCAPES: out.append(TOML_ESCAPES[c])
                else: err(f"bad escape \\{c}")
            else: out.append(s[i])
            i += 1
        if i >= n: err("unterminated string")
        i += 1
        return "".join(out)

    def key():
        nonlocal i
        parts = []
        while True:
            skip()
            if s[i:i + 1] in ('"', "'"): parts.append(string())
            else:
                m = re.compile(r"[A-Za-z0-9_-]+").match(s, i)
                if not m: err("expected a key")
                parts.append(m.group()); i = m.end()
            skip()
            if s[i:i + 1] == ".": i += 1
            else: return parts

    def value():
        nonlocal i
        c = s[i:i + 1]
        if c in ('"', "'"): return string()
        if c == "[":
            i += 1; arr = []
            while True:
                skip(True)
                if s[i:i + 1] == "]": i += 1; return arr
                arr.append(value()); skip(True)
                if s[i:i + 1] == ",": i += 1
                elif s[i:i + 1] != "]": err("expected , or ] in array")
        if c == "{":
            i += 1; tab = {}
            while True:
                skip()
                if s[i:i + 1] == "}": i += 1; return tab
                ks = key(); skip()
                if s[i:i + 1] != "=": err("expected =")
                i += 1; skip(); put(tab, ks, value()); skip()
                if s[i:i + 1] == ",": i += 1
                elif s[i:i + 1] != "}": err("expected , or } in inline table")
        m = re.compile(r"[^\s,\]\}#]+").match(s, i)
        if not m: err("expected a value")
        tok = m.group(); i = m.end()
        if tok in ("true", "false"): return tok == "true"
        if re.fullmatch(r"\d{4}-\d\d-\d\d", tok): return tok  # a bare date; tomllib gives a date object, the tool str()s it
        try: return int(tok.replace("_", ""), 0)
        except ValueError: pass
        try: return float(tok.replace("_", ""))
        except ValueError: err(f"cannot read the value {tok!r}")

    def put(tab, ks, v):
        for k in ks[:-1]:
            tab = tab.setdefault(k, {})
            if not isinstance(tab, dict): err(f"{k} is not a table")
        if ks[-1] in tab: err(f"duplicate key {ks[-1]}")
        tab[ks[-1]] = v

    while True:
        skip(True)
        if i >= n: return root
        if s[i] == "[":
            if s.startswith("[[", i): err("arrays of tables are not supported by the built-in reader")
            i += 1; ks = key(); skip()
            if s[i:i + 1] != "]": err("expected ]")
            i += 1; cur = root
            for k in ks:
                cur = cur.setdefault(k, {})
                if not isinstance(cur, dict): err(f"{k} is not a table")
        else:
            ks = key(); skip()
            if s[i:i + 1] != "=": err("expected =")
            i += 1; skip(); put(cur, ks, value())
        skip()
        if i < n and s[i] not in "\r\n": err("unexpected text after a value")


def parse_toml(text):
    return tomllib.loads(text) if tomllib else parse_toml_mini(text)


def merge(base, new):
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict): merge(base[k], v)
        else: base[k] = copy.deepcopy(v)
    return base


def load_config(siwithin_home):
    cfg, path = copy.deepcopy(DEFAULT_CONFIG), os.path.join(siwithin_home, "config.toml")
    problems, present = [], os.path.isfile(path)
    if present:
        try:
            with open(path, encoding="utf-8") as f: user = parse_toml(f.read())
        except (OSError, ValueError) as x: raise Refused(f"cannot read {path}: {x}")
        for k in user:
            if k not in cfg: problems.append(f"config.toml: unknown section [{k}] ignored")
        for a in (user.get("adapters") or {}):
            if a not in cfg["adapters"]: cfg["adapters"][a] = copy.deepcopy(BLANK_ADAPTER)
        merge(cfg, user)
    for a, ad in cfg["adapters"].items():
        for f in ad:
            if f not in BLANK_ADAPTER: problems.append(f"config.toml: adapter {a}: unknown field {f!r} ignored")
        for f, blank in BLANK_ADAPTER.items():
            if f not in ad: ad[f] = copy.deepcopy(blank)
            elif type(ad[f]) is not type(blank): raise Refused(f"config.toml: adapter {a}: {f} must be a {type(blank).__name__}")
    return cfg, path, present, problems


# ---- what each CLI's output says: one feed function per output format; each reads one parsed event into the state -----------------

def new_state(model):
    return {"model": model, "text": "", "key_source": None, "init": False, "session": None, "turns": None, "usage": {}, "cli_costs": {}, "cli_total": None,
            "denials": [], "failed": None, "complete": False, "open_turns": 0, "closed_turns": 0, "last_message": None, "errors": [],
            "msgs": {}, "last_msg": None, "assistant_events": 0, "usage_events": 0}


STREAM_FIELDS = (("in", "input_tokens"), ("cache_write", "cache_creation_input_tokens"), ("cache_read", "cache_read_input_tokens"), ("out", "output_tokens"))


def streamed_usage(msgs):
    usage = {}
    for model, counts in msgs.values():
        acc = usage.setdefault(model, {"in": 0, "cache_write": 0, "cache_read": 0, "out": 0, "searches": 0})
        for k in counts: acc[k] += counts[k]
    return usage


def feed_message_usage(st, msg):
    """One assistant event: message.model and message.usage. Each message id counts once; the usage is read as it streams, before any result."""
    st["assistant_events"] += 1
    u = msg.get("usage") if isinstance(msg, dict) else None
    if not isinstance(u, dict) or not any(isinstance(u.get(f), int) for _, f in STREAM_FIELDS): return  # no usage on this event: the run's notes say so
    st["usage_events"] += 1
    model = msg.get("model") or st["model"] or "unknown"
    counts = {k: max(0, u[f]) if isinstance(u.get(f), int) and not isinstance(u.get(f), bool) else 0 for k, f in STREAM_FIELDS}
    if not any(counts.values()): return  # a synthetic message with nothing spent
    fp = (model, tuple(counts.values()))
    key = msg.get("id")
    if not key:  # no id on the event: the same model and counts as the event before is the same response again; one that differs is a new response
        key = st["last_msg"][0] if st["last_msg"] and st["last_msg"][1] == fp else f"#{len(st['msgs'])}"
    st["last_msg"] = (key, fp)
    if key in st["msgs"]: counts = {k: max(v, st["msgs"][key][1][k]) for k, v in counts.items()}
    st["msgs"][key] = (model, counts)
    st["usage"] = streamed_usage(st["msgs"])


def feed_claude(st, e, ad):
    # stream-json: the init event names the key source; assistant events carry each response's usage (input and cache tokens true, output tokens a placeholder);
    # the result event, last, carries modelUsage (per-model tokens and the CLI's own cost) and total_cost_usd, and replaces what streamed
    t = e.get("type")
    if t == "system" and e.get("subtype") == "init":
        st["init"], st["key_source"], st["session"] = True, e.get("apiKeySource"), e.get("session_id")
    elif t == "assistant" and not st["complete"]: feed_message_usage(st, e.get("message"))
    elif t == "result":
        st["complete"], st["text"], st["turns"] = True, e.get("result") or "", e.get("num_turns")
        st["session"] = st["session"] or e.get("session_id")
        st["usage"] = {}
        for m, u in (e.get("modelUsage") or {}).items():
            st["usage"][m] = {"in": u.get("inputTokens") or 0, "cache_write": u.get("cacheCreationInputTokens") or 0, "cache_read": u.get("cacheReadInputTokens") or 0,
                              "out": u.get("outputTokens") or 0, "searches": u.get("webSearchRequests") or 0}
            st["cli_costs"][m] = u.get("costUSD")
        st["cli_total"] = e.get("total_cost_usd")
        st["denials"] = [(x.get("tool_name"), json.dumps(x.get("tool_input"))[:160]) for x in (e.get("permission_denials") or [])]
        if e.get("is_error") or e.get("terminal_reason") == "api_error": st["failed"] = f"api error {e.get('api_error_status')}: {(e.get('result') or '')[:80]}"
        elif e.get("subtype") != "success": st["failed"] = f"result {e.get('subtype')}"


def feed_codex(st, e, ad):
    # exec --json: thread.started, turn.started, item.*, turn.completed (the only event with usage), turn.failed, error; no cost field is documented
    t = e.get("type")
    if t == "thread.started": st["session"] = e.get("thread_id")
    elif t == "turn.started": st["open_turns"] += 1
    elif t == "turn.completed":
        st["open_turns"] = max(0, st["open_turns"] - 1); st["closed_turns"] += 1; st["turns"] = st["closed_turns"]
        u, cached = e.get("usage") or {}, (e.get("usage") or {}).get("cached_input_tokens") or 0
        inp = u.get("input_tokens") or 0
        acc = st["usage"].setdefault(st["model"], {"in": 0, "cache_write": 0, "cache_read": 0, "out": 0, "searches": 0})
        acc["in"] += max(0, inp - cached) if ad["input_includes_cached"] else inp
        acc["cache_read"] += cached; acc["out"] += u.get("output_tokens") or 0
        st["complete"] = st["open_turns"] == 0
    elif t == "turn.failed": st["failed"] = "turn failed: " + str(((e.get("error") or {}).get("message")) or "")[:80]
    elif t == "item.completed":
        item = e.get("item") or {}
        if item.get("type") == "agent_message": st["last_message"] = item.get("text") or ""
    elif t == "error": st["errors"].append(str(e.get("message") or "")[:120])


PARSERS = {"claude-stream-json": feed_claude, "codex-jsonl": feed_codex}


# ---- money -------------------------------------------------------------------------------------------------------------------

def model_cost(prices, model, u):
    p = prices.get(model)
    if not (isinstance(p, list) and len(p) == 4): return None
    return (u["in"] * p[0] + u["cache_write"] * p[1] + u["cache_read"] * p[2] + u["out"] * p[3]) / 1e6 + u["searches"] * float(prices.get("web_search") or 0)


def true_total(usage, cli_costs, prices, factors):
    """True dollars at the published rates; a model with no price falls back to the CLI's own figure over its factor, and says so."""
    total, notes = 0.0, []
    for m, u in usage.items():
        c = model_cost(prices, m, u)
        if c is None:
            cc, f = cli_costs.get(m), factors.get(m) or 1
            if cc is None: notes.append(f"no price for {m} in [prices] and the CLI gave no cost: its spend is missing from the true figure"); continue
            c = cc / f; notes.append(f"no price for {m} in [prices]: its true cost is the CLI's ${cc:.4f} over factor {f}")
        total += c
    return round(total, 4), notes


def factor_notes(usage, cli_costs, prices, factors, version):
    """The factor is stale when the CLI's cost over the true cost is more than four times the factor or less than a quarter of it."""
    notes = []
    for m, u in usage.items():
        c, cc, f = model_cost(prices, m, u), cli_costs.get(m), factors.get(m) or 1
        if c is not None and cc is not None and c >= 0.01 and not f / 4 <= cc / c <= f * 4:
            notes.append(f"factor {f} for {m} looks stale on CLI {version}: the CLI's ${cc:.4f} against true ${c:.4f}, a ratio of {cc / c:.2f}, outside a quarter to four times the factor; set it under [factors]")
    return notes


def unpriced_models(usage, prices):
    return sorted(m for m in usage if not (isinstance(prices.get(m), list) and len(prices[m]) == 4))


def ledger_total(path):
    total, runs = 0.0, 0
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\d{4}-\d\d-\d\d .*?\| true \$([0-9]+(?:\.[0-9]+)?)", line)
                if m: total += float(m.group(1)); runs += 1
    except FileNotFoundError: pass
    return round(total, 4), runs


def num(x):
    return f"{x:.4f}".rstrip("0").rstrip(".") if x else "0"


# ---- the fence -----------------------------------------------------------------------------------------------------------------

SB_TEMPLATE = """(version 1)
; @NAME@: the home folder is refused whole, for reads and writes, and only what the run needs is allowed back.
; A later rule wins over an earlier one, so every allow sits after the deny it overrides.
(allow default)
; no writes in the home, in the temp roots other sessions keep their scratch files in, or in the roots a user can write to
@DENY_WRITE@
; no reads in the home
@DENY_READ@
; allowed back: the CLI's binary, caches, logs and keychain, user packages, the shell's rc files, git's config
@ALLOW_READ@
@ALLOW_WRITE@
; no opening of apps, screenshots or scripting of the machine from inside the run
@DENY_EXEC@
"""


def sb_str(p):
    if any(ord(c) < 32 for c in p): raise Refused(f"a path with a control character cannot go in the fence profile: {p!r}")
    return '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sb_rule(action, op, *filters):
    """One rule line, or none: a rule with no filter would apply to everything."""
    return f"({action} {op} " + " ".join(filters) + ")" if filters else ""


def sub(p): return f"(subpath {sb_str(p)})"
def lit(p): return f"(literal {sb_str(p)})"
def under(a, b): return a == b or a.startswith(b.rstrip("/") + "/")


def ancestors(p, home):
    out = []
    while under(p, home) and p != home: p = os.path.dirname(p); out.append(p)
    return out


def fence_profile(c):
    """c: home, folders (the first writable unless readonly), readonly, siwithin_home, config_dir, run, tmp (bool), last_message (bool), fence (config section), read_extra, write_extra."""
    home, f = c.home, c.fence
    reads = [os.path.join(home, r) for r in f["read_home"]] + list(c.read_extra)
    writes = [os.path.join(home, w) for w in f["write_home"]] + list(c.write_extra)
    head = SB_TEMPLATE.replace("@NAME@", NAME)
    head = (head.replace("@DENY_WRITE@", sb_rule("deny", "file-write*", sub(home), *[sub(r) for r in f["deny_write"]]))
                .replace("@DENY_READ@", sb_rule("deny", "file-read*", sub(home)))
                .replace("@ALLOW_READ@", sb_rule("allow", "file-read*", *[sub(r) for r in reads], *[lit(os.path.join(home, r)) for r in f["rc_files"]]))
                .replace("@ALLOW_WRITE@", sb_rule("allow", "file-write*", *[sub(w) for w in writes]))
                .replace("@DENY_EXEC@", sb_rule("deny", "process-exec", *[lit(x) for x in f["deny_exec"]])))
    out = [x for x in head.split("\n") if x]  # a rule with nothing to list is left out, not written empty
    out.append("; this run's folders, readable" + ("" if c.readonly else "; the first also writable"))
    out += [sb_rule("allow", "file-read*", sub(d)) for d in c.folders]
    if not c.readonly: out.append(sb_rule("allow", "file-write*", sub(c.folders[0])))
    out += ["; the tool's own home stays refused whatever the run's folder is: its config, cap, ledger, and the briefs and events of other runs",
            sb_rule("deny", "file-read*", sub(c.siwithin_home)), sb_rule("deny", "file-write*", sub(c.siwithin_home)),
            "; the CLI's own config directory, where it keeps its state and finds no login unless one was put there",
            sb_rule("allow", "file-read*", sub(c.config_dir)), sb_rule("allow", "file-write*", sub(c.config_dir))]
    allowed = list(c.folders) + reads + writes + [c.config_dir, c.run]
    if c.tmp:
        out += ["; the run's temp root, where the CLI keeps each command's output", sb_rule("allow", "file-read*", sub(c.run + "/tmp")), sb_rule("allow", "file-write*", sub(c.run + "/tmp"))]
        allowed.append(c.run + "/tmp")
    if c.last_message:
        out += ["; the one file the CLI writes its final message to", sb_rule("allow", "file-write*", lit(c.run + "/last-message.txt"))]
    # the CLI vets each folder above the ones it is given, which needs their metadata and no more
    meta = sorted({a for p in allowed for a in ancestors(p, home)} | {home})
    out += ["; the folders above the allowed ones, metadata only", sb_rule("allow", "file-read-metadata", *[lit(p) for p in meta]), ""]
    return "\n".join(out)


def forbidden_reason(folder, home, roots):
    """A reason this folder is not given to a run, or None. Compared case-insensitively: the volume usually is."""
    fc, hc = folder.casefold(), home.casefold()
    if fc == hc or under(hc, fc): return "is the home folder or holds it"
    for r, why in roots:
        rc = r.casefold()
        if under(fc, rc): return f"is {r} or inside it ({why})"
        if under(rc, fc): return f"holds {r} ({why})"
    return None


# ---- the plan: everything a run needs decided, with no side effects, so --dry-run and a real run print and do the same thing -------

def real(p): return os.path.realpath(os.path.abspath(os.path.expanduser(p)))


def derive_home():
    h = os.path.expanduser("~")
    if not h or h == "~" or not os.path.isdir(h): raise Refused("cannot derive the home folder: set HOME")
    r = os.path.realpath(h)
    if r == "/": raise Refused("the home folder is /: a fence around it would be no fence")
    return r


def slugify(name): return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-") or "run"


def make_plan(o, cfg, cfg_info, home, siwithin_home, brief, dry, now):
    P = SimpleNamespace(checks=[], notes=[], dry=dry)
    chk = lambda level, text: P.checks.append((level, text))
    if sys.platform == "win32": raise Refused(f"{NAME} needs macOS sandbox-exec and refuses to run on Windows rather than run without a fence; see {ROADMAP}")
    if sys.platform != "darwin": chk("refuse", f"{NAME} needs macOS sandbox-exec and refuses to run on {sys.platform} rather than run without a fence; see {ROADMAP}")
    else: chk("ok", "platform: macOS, sandbox-exec" + ("" if os.path.exists(SANDBOX_EXEC) else " MISSING"))
    if sys.platform == "darwin" and not os.path.exists(SANDBOX_EXEC): chk("refuse", f"{SANDBOX_EXEC} not found")
    cfg_path, present, problems = cfg_info
    chk("ok" if present else "warn", f"config: {cfg_path} " + (f"read with {'tomllib' if tomllib else 'the built-in reader (Python < 3.11)'}" if present else "not found, built-in defaults in use"))
    for t in problems: chk("warn", t)

    # adapter
    d = cfg["defaults"]; name = o.adapter or d["adapter"]; P.adapter = name
    ad = cfg["adapters"].get(name)
    if ad is None: raise Refused(f"unknown adapter {name!r}; the config declares {', '.join(sorted(cfg['adapters']))}")
    P.ad = ad
    if not ad["bin"]: raise Refused(f"adapter {name}: bin is empty")
    if ad["output"] not in PARSERS: raise Refused(f"adapter {name}: output {ad['output']!r} is not one of {', '.join(PARSERS)}")
    if ad["brief"] not in ("stdin", "arg"): raise Refused(f"adapter {name}: brief must be stdin or arg")
    unc = [f for f, v in ad.items() if v == UNCONFIRMED]
    if unc: chk("warn", f"adapter {name}: fields marked {UNCONFIRMED}, so options needing them are refused: {', '.join(unc)}")
    if ad["unconfirmed"]: chk("warn", f"adapter {name}: assumptions {UNCONFIRMED} in the CLI's docs: {', '.join(ad['unconfirmed'])}")
    if not ad["measured"]: chk("warn", f"adapter {name}: built from documentation, not measured on any CLI version")

    # options
    P.readonly = o.readonly
    P.budget = o.budget if o.budget is not None else float(d["budget"])
    P.timeout = o.timeout if o.timeout is not None else int(d["timeout"])
    if P.budget <= 0 or P.timeout <= 0 or (o.turns is not None and o.turns <= 0): raise Refused("--budget, --turns and --timeout must be above zero")
    if o.out and o.readonly: raise Refused("--out with --readonly: a readonly run leaves its folder as it found it; take the result from the run's result.md")
    P.slug = slugify(o.name); P.effort = o.effort; P.label = o.model or "default"  # the label is what was typed, an alias or an id, as in the ledger line

    def need(field, what):
        v = ad[field]
        if v == UNCONFIRMED: raise Refused(f"adapter {name}: {field} is {UNCONFIRMED} (not in the documentation read), so {what} is refused; set {field} in config.toml if you know the flag")
        if not v: raise Refused(f"adapter {name} has no way to set {what}")
        return v

    # folders
    roots = [(os.path.join(home, ".ssh"), "keys"), (os.path.join(home, ".config"), "other tools' settings and tokens"), (os.path.join(home, "Library"), "app data and keychains"), (siwithin_home, f"{NAME}'s own home")]
    roots += [(real(a["own_dir"]), f"the {n} CLI's own config directory") for n, a in sorted(cfg["adapters"].items()) if a["own_dir"]]
    roots += [(real(x), "listed under [never]") for x in cfg["never"]["folders"]]
    dirs = []
    for f in [o.dir] + list(o.read):
        r = real(f)
        if not os.path.isdir(r): raise Refused(f"{r} is not a folder")
        why = forbidden_reason(r, home, roots)
        if why: raise Refused(f"{r} {why}; no run is given the home root, ~/.ssh, ~/.config, ~/Library, a CLI's own config directory, {NAME}'s home or a [never] folder")
        if r not in dirs: dirs.append(r)
    P.dirs, P.reads = dirs, dirs[1:]

    # model, budget
    model = ad["aliases"].get(o.model, o.model) if o.model else None
    P.model = model
    prices, factors = cfg["prices"], cfg["factors"]
    priced = model is not None and isinstance(prices.get(model), list) and len(prices[model]) == 4
    P.mode = "flag" if ad["budget_flag"] not in ("", UNCONFIRMED) else {"message": "stream", "turn": "turn"}.get(ad["usage_at"], "none")
    P.soft = o.soft_budget
    P.also_stream = P.mode == "flag" and ad["usage_at"] == "message"  # the CLI's flag stops the run, and so does the runner, from the usage the CLI streams
    if P.mode == "none": raise Refused(f"adapter {name} has no budget flag and reports no usage while it runs, so its budget cannot be kept; refusing rather than run unbudgeted")
    if P.mode != "flag":
        if not model: raise Refused(f"--model is needed: adapter {name} reports tokens and no cost, so the run is priced by model id from [prices]")
        if not priced: raise Refused(f"no price for {model} in [prices]: adapter {name} reports tokens and no cost, so the budget cannot be kept without one")
    if P.mode == "turn" and not o.soft_budget:
        raise Refused(f"adapter {name} reports usage only when a turn ends, so --budget cannot stop a run mid-turn and one long turn can pass it unseen; "
                      "pass --soft-budget to accept a budget checked when each turn ends, or use an adapter with a budget flag")
    if model and not priced:
        chk("warn", f"{model} has no entry in [prices]: its true cost is the CLI's own figure over its factor"
            + ("; the streamed stop cannot price it, so only the CLI's flag at budget x factor stops the run, and the stop is approximate" if P.also_stream else ""))
    if not model: chk("warn", "no --model: the CLI picks its own default, and the budget factor 1 is assumed"
                      + ("; the streamed stop prices each message by the model it reports, and a model with no entry in [prices] is left to the CLI's flag" if P.also_stream else ""))
    factor = factors.get(model) or 1 if model else 1
    P.factor, P.cli_budget = factor, P.budget * factor
    ro = str(prices.get("read_on") or "")
    try:
        age = (now.date() - datetime.date.fromisoformat(ro)).days
        chk("warn" if age > PRICE_STALE_DAYS else "ok", f"prices: read on {ro} from {prices.get('source') or 'an unnamed source'}" + (f", {age} days ago: check them against the published rates" if age > PRICE_STALE_DAYS else ""))
    except ValueError: chk("warn", "prices: no readable read_on date in [prices]")

    # turns
    P.turns = None
    if o.turns is not None: P.turns = o.turns; need("turns_flag", "a turn limit")
    elif ad["turns_flag"] not in ("", UNCONFIRMED) and d.get("turns"): P.turns = int(d["turns"])
    if P.turns is None and o.turns is None: chk("warn", f"adapter {name} has no turn limit: only --timeout and the budget stop a run")

    # api key check
    req = o.require_api_key if o.require_api_key is not None else ad["require_api_key"]
    P.require_key = req
    if req and not (ad["auth_status_args"] or ad["key_sources_ok"]): raise Refused(f"--require-api-key: adapter {name} has no auth status command and no key source in its events, so billing to an API key cannot be checked")
    chk("ok" if req else "warn", f"api key: " + ("required: the CLI's auth status is asked before launch and the run is killed at its init event if the key source is not one of " + ", ".join(ad["key_sources_ok"]) if req else "not required: the run may be billed to a login"))

    # cap and ledger
    P.cap_path, P.ledger_path = os.path.join(siwithin_home, "cap"), os.path.join(siwithin_home, "ledger.md")
    P.total, P.nruns = ledger_total(P.ledger_path)
    try:
        with open(P.cap_path, encoding="utf-8") as f: P.cap = float(f.read().strip())
    except (OSError, ValueError) as x: P.cap = None; chk("refuse", f"no readable cap in {P.cap_path} ({x}); write the dollars all runs together may spend, e.g.  echo 20 > {P.cap_path}")
    if P.cap is not None:
        if P.total + P.budget > P.cap: chk("refuse", f"ledger true total ${P.total:.2f} + budget ${P.budget:.2f} passes the cap ${P.cap:.2f} in {P.cap_path}")
        else: chk("ok", f"cap: ledger true total ${P.total:.2f} + budget ${P.budget:.2f} is within the cap ${P.cap:.2f}")

    # environment, config dir, CLI
    P.siwithin_home, P.home = siwithin_home, home
    P.config_dir = real(os.path.expanduser(ad["config_dir"].replace("{fence_home}", siwithin_home))) if ad["config_dir"] else None
    if not P.config_dir: raise Refused(f"adapter {name}: config_dir is empty; a run needs a config directory of its own")
    stamp = now.strftime("%Y-%m-%d-%H%M"); run, k = os.path.join(siwithin_home, "runs", f"{stamp}-{P.slug}"), 2
    while os.path.exists(run): run = os.path.join(siwithin_home, "runs", f"{stamp}-{P.slug}-{k}"); k += 1
    P.run, P.stamp = run, stamp
    env = {k: os.environ[k] for k in cfg["env"]["pass"] + ad["env_pass"] if k in os.environ}
    if ad["config_dir_env"]: env[ad["config_dir_env"]] = P.config_dir
    if ad["tmp_env"]: env[ad["tmp_env"]] = run + "/tmp"
    if P.effort and ad["effort_env"]: env[ad["effort_env"]] = P.effort
    P.env = env
    P.bin_path = shutil.which(ad["bin"], path=env.get("PATH") or os.defpath)
    if P.bin_path: chk("ok", f"cli: {ad['bin']} at {P.bin_path}")
    else: chk("warn" if dry else "refuse", f"cli: {ad['bin']} not found on PATH" + ("; a real run would refuse" if dry else ""))
    chk("ok" if os.path.isdir(P.config_dir) else "warn", f"config directory of the run: {P.config_dir}" + ("" if os.path.isdir(P.config_dir) else " (created on the first run)"))
    chk("ok", "environment passed, names only: " + ", ".join(sorted(env)) + "; nothing else is inherited")

    # command
    cmd = [P.bin_path or ad["bin"]]
    fill = lambda x: x.replace("{run}", run).replace("{dir}", dirs[0]).replace("{fence_home}", siwithin_home)
    cmd += [fill(a) for a in ad["args"]]
    if P.effort: cmd += [need("effort_flag", "--effort"), P.effort]
    if model: cmd += [need("model_flag", "--model"), model]
    if P.turns is not None: cmd += [ad["turns_flag"], str(P.turns)]
    if P.mode == "flag": cmd += [ad["budget_flag"], num(round(P.cli_budget, 4))]
    if ad["add_dir_flag"] not in ("", UNCONFIRMED):
        for r in dirs: cmd += [ad["add_dir_flag"], r]
    elif P.reads: chk("warn", f"adapter {name} is not told about --read folders (add_dir_flag {'is ' + UNCONFIRMED if ad['add_dir_flag'] else 'is empty'}): the fence lets the run read them, the CLI is not pointed at them")
    if o.resume: cmd += [need("resume_flag", "--resume"), o.resume]
    if ad["cwd_flag"]: cmd += [ad["cwd_flag"], dirs[0]]
    P.last_message = ad["last_message_flag"] not in ("", UNCONFIRMED)
    if P.last_message: cmd += [ad["last_message_flag"], run + "/last-message.txt"]
    cmd += [fill(a) for a in (ad["args_readonly"] if o.readonly else ad["args_write"])] + [fill(a) for a in ad["extra_args"]]
    P.shown = cmd + ([ad["brief_arg"]] if ad["brief_arg"] else []) + (["<brief.md>"] if ad["brief"] == "arg" else [])
    P.cmd = cmd + ([ad["brief_arg"]] if ad["brief_arg"] else []) + ([brief] if ad["brief"] == "arg" and brief is not None else [])
    P.brief = brief
    if brief is None: chk("warn" if dry else "refuse", "brief: none on stdin")
    elif not brief.strip(): chk("refuse", "brief: empty on stdin")
    else: chk("ok", f"brief: {len(brief.encode('utf-8'))} bytes on stdin, passed to the CLI by {ad['brief']}" + ("; it is visible in the process list" if ad["brief"] == "arg" else ""))

    # the fence
    bin_dirs = []
    if P.bin_path:
        rp = os.path.realpath(P.bin_path)
        bin_dirs = [q for q in (os.path.dirname(os.path.abspath(P.bin_path)), os.path.dirname(rp), rp.split("/lib/node_modules/")[0] if "/lib/node_modules/" in rp else None) if q and under(q, home) and q != home]
    P.profile = fence_profile(SimpleNamespace(home=home, folders=dirs, readonly=o.readonly, siwithin_home=siwithin_home, config_dir=P.config_dir, run=run, tmp=bool(ad["tmp_env"]),
                                              last_message=P.last_message, fence=cfg["fence"], read_extra=[os.path.join(home, r) for r in ad["read_home"]] + bin_dirs,
                                              write_extra=[os.path.join(home, w) for w in ad["write_home"]]))
    P.sb_path = os.path.join(run, "fence.sb")
    P.argv = [SANDBOX_EXEC, "-f", P.sb_path] + P.cmd
    P.out_path = None
    if o.out:
        cand = os.path.realpath(os.path.join(dirs[0], os.path.expanduser(o.out)))
        if not under(cand, dirs[0]) or cand == dirs[0]: raise Refused(f"--out {o.out} resolves to {cand}, outside the run's folder {dirs[0]}; {NAME} writes nowhere else")
        P.out_path = cand
    P.done_text, P.absent_text = o.done, o.absent
    P.measured = ad["measured"]
    P.prices_read_on = ro or "unknown"
    P.rates = " / ".join(str(x) for x in prices[model]) if priced else None
    return P


def show_plan(P):
    pr = lambda *a: print(*a, flush=True)
    pr(f"{NAME} {VERSION} dry run: nothing is run, nothing is written")
    pr("\n== command ==\n" + shlex.join([SANDBOX_EXEC, "-f", P.sb_path] + P.shown))
    pr(f"cwd: {P.dirs[0]}\nstdin: " + ("the brief" if P.ad["brief"] == "stdin" else "none") + f"\nrun folder: {P.run}")
    pr("\n== fence profile ==\n" + P.profile)
    pr("== config checks ==")
    for lv, t in P.checks: pr(f"{lv:<6} {t}")
    pr("\n== budget ==")
    pr(f"budget this run: ${P.budget:.2f} true dollars, at the [prices] rates read on {P.prices_read_on}")
    if P.model: pr(f"model: {P.model}, rates per million tokens (input, cache write, cache read, output): {P.rates or 'none listed'}")
    if P.mode == "flag":
        flag = f"{P.ad['budget_flag']} {num(round(P.cli_budget, 4))} (factor {P.factor} between the CLI's units and true dollars)"
        if P.also_stream:
            pr(f"enforced twice:\n  1. by the CLI: {flag}; {NAME} reads the true cost at the end")
            pr(f"  2. by {NAME}, from the stream: each assistant event's usage is priced at the [prices] rates, once per message id, and the run's process group is killed when the true cost "
               f"reaches ${P.budget:.2f}: \"killed: budget ${P.budget:.2f} reached at $<true> true\"")
            pr("     the stream's output tokens are a placeholder until the result event, so this figure is a lower bound and the stop can come after the budget on a run heavy in output")
            if P.model and not P.rates: pr(f"     no price for {P.model} in [prices]: this stop cannot count it, and only the CLI's flag stops the run")
            if not P.model: pr("     no --model: a model the stream reports with no price in [prices] is not counted, and only the CLI's flag stops the run")
            pr("     if the stream carries no usage, the CLI's flag alone enforces the budget and the summary notes say so")
        else: pr(f"enforced by the CLI: {flag}; {NAME} reads the true cost at the end")
    elif P.mode == "stream": pr(f"enforced by {NAME}: usage is read as it streams and the run is killed when it reaches ${P.budget:.2f}")
    else: pr(f"checked by {NAME} when each turn ends (--soft-budget): the run is killed between turns once usage reaches ${P.budget:.2f}; one long turn can pass it unseen")
    pr(f"time: killed after {P.timeout}s by a timer, always")
    if P.cap is None: pr(f"cap: unreadable ({P.cap_path})")
    else:
        after = P.total + P.budget
        pr(f"ledger: ${P.total:.2f} true over {P.nruns} runs ({P.ledger_path})\ncap: ${P.cap:.2f}\nworst case after this run: ${P.total:.2f} + ${P.budget:.2f} = ${after:.2f} of ${P.cap:.2f}, "
           + (f"within the cap, ${P.cap - after:.2f} left" if after <= P.cap else f"over the cap by ${after - P.cap:.2f}: REFUSED"))


# ---- the run -------------------------------------------------------------------------------------------------------------------

def on_term(signum, frame):
    raise KeyboardInterrupt


def kill_group(proc):  # the whole group: the CLI's own tool processes die with it
    try: os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try: proc.kill()
        except OSError: pass


def acquire_lock(path):
    import fcntl  # POSIX only; the platform check has already refused everything else
    lock = open(path, "a+")
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.seek(0); holder = lock.read().strip() or "holder unknown"
        raise Refused(f"another run is live, {holder}; one run at a time")
    return lock


def probe(P, args):
    return subprocess.run([SANDBOX_EXEC, "-f", P.sb_path, P.bin_path] + args, capture_output=True, text=True, env=P.env, cwd=P.dirs[0], timeout=60)


def execute(P, cfg):
    ad, run, d = P.ad, P.run, P.dirs[0]
    os.makedirs(run + "/tmp" if ad["tmp_env"] else run, mode=0o700)
    os.makedirs(P.config_dir, mode=0o700, exist_ok=True)
    with open(f"{run}/brief.md", "w", encoding="utf-8") as f: f.write(P.brief)
    with open(P.sb_path, "w", encoding="utf-8") as f: f.write(P.profile)
    notes = list(P.notes)
    if ad["unconfirmed"]: notes.append(f"adapter {P.adapter} rests on assumptions {UNCONFIRMED} in the CLI's docs: {', '.join(ad['unconfirmed'])}")

    def refuse_before_launch(msg):
        with open(f"{run}/summary.json", "w", encoding="utf-8") as f: json.dump({"status": f"refused: {msg}", "run": run}, f, indent=1)
        raise Refused(msg)

    version = None
    try:
        if ad["version_args"]:
            r = probe(P, ad["version_args"]); m = re.search(r"\d+\.\d+\.\d+\S*", r.stdout + r.stderr)
            version = m.group() if m else None
        if P.require_key and ad["auth_status_args"]:
            r = probe(P, ad["auth_status_args"]); auth = json.loads(r.stdout)
            if auth.get("authMethod") not in ad["auth_methods_ok"] or auth.get("orgId"):
                refuse_before_launch(f"the CLI's auth in {P.config_dir} is {auth.get('authMethod')!r}, org {auth.get('orgId')!r}, so the run might be billed to a login and not an API key "
                                     f"(a CLI with a login in its config directory signs with the login whatever its events say); put an API key where the CLI finds it, or pass --no-require-api-key")
    except (ValueError, subprocess.TimeoutExpired, OSError) as x: refuse_before_launch(f"{ad['bin']} gave no usable answer to its version or auth status check ({x})")
    if version is None: notes.append(f"no version read from {ad['bin']} {' '.join(ad['version_args'])}")
    elif version not in P.measured: notes.append(f"CLI {version}, not one of {', '.join(P.measured) or 'none'} that the adapter was measured on: the command shape, the auth finding and any factor may differ")

    with open(f"{run}/command.txt", "w", encoding="utf-8") as f:
        f.write(shlex.join([SANDBOX_EXEC, "-f", P.sb_path] + P.shown) + "\n" + "environment: " + ", ".join(sorted(P.env)) + f"\ncli: {version}\n")
    feed = PARSERS[ad["output"]]
    st = new_state(P.model)
    killed = [None]
    t0 = datetime.datetime.now()
    old_term = signal.signal(signal.SIGTERM, on_term)  # a terminated tool still writes its summary and ledger line
    with open(f"{run}/events.jsonl", "w", encoding="utf-8") as ev, open(f"{run}/stderr.txt", "w", encoding="utf-8") as er:
        proc = subprocess.Popen(P.argv, stdin=subprocess.PIPE if ad["brief"] == "stdin" else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=er, text=True,
                                encoding="utf-8", errors="replace", cwd=d, env=P.env, start_new_session=True)

        def stop(kind, text):
            if killed[0] is None: killed[0] = (kind, text); kill_group(proc)

        if ad["brief"] == "stdin":
            def feed_stdin():
                try: proc.stdin.write(P.brief); proc.stdin.close()
                except (BrokenPipeError, OSError): pass
            threading.Thread(target=feed_stdin, daemon=True).start()
        timer = threading.Timer(P.timeout, lambda: stop("timeout", f"timeout {P.timeout}s")); timer.daemon = True; timer.start()  # time is kept by a timer, always
        grace = None
        checked = False
        try:
            for line in proc.stdout:
                ev.write(line); ev.flush()
                try: e = json.loads(line)
                except ValueError: continue
                if not isinstance(e, dict): continue
                feed(st, e, ad)
                if P.require_key and ad["key_sources_ok"] and st["init"] and not checked:
                    checked = True
                    if st["key_source"] not in ad["key_sources_ok"]:
                        stop("key", f"killed: key source is {st['key_source']!r}, not one of {', '.join(ad['key_sources_ok'])}, so the run would not bill an API key"); break
                if P.mode in ("stream", "turn"):  # the CLI has no budget flag: the budget is kept here, from the usage it streams
                    running = true_total(st["usage"], st["cli_costs"], cfg["prices"], cfg["factors"])[0]
                    if running >= P.budget:
                        reason = f"killed: budget ${P.budget:.2f} reached at ${running:.4f} true"
                        if P.mode == "stream" or e.get("type") == "turn.started": stop("budget", reason); break
                        # usage arrives when a turn ends: a run that ends with its turn is left to exit and is reported over budget, one that starts another turn is killed
                        if grace is None: grace = threading.Timer(5, lambda: stop("budget", reason)); grace.daemon = True; grace.start()
                elif P.also_stream and e.get("type") == "assistant":  # the CLI's flag stops at budget x factor; this stops at the true budget, whatever the factor says
                    running = true_total(st["usage"], st["cli_costs"], cfg["prices"], cfg["factors"])[0]
                    if running >= P.budget: stop("budget", f"killed: budget ${P.budget:.2f} reached at ${running:.4f} true"); break
        except KeyboardInterrupt: stop("interrupted", "killed: interrupted")
        finally:
            timer.cancel()
            if grace: grace.cancel()
            signal.signal(signal.SIGTERM, old_term)
        try: proc.wait(timeout=30)
        except subprocess.TimeoutExpired: kill_group(proc); proc.wait()
    mins = (datetime.datetime.now() - t0).total_seconds() / 60

    text = st["text"]
    if P.last_message:  # the adapter has the CLI write its final message to a file; the last message in the events is the fallback
        try:
            with open(f"{run}/last-message.txt", encoding="utf-8") as f: text = f.read()
        except OSError: text = st["last_message"] or ""
    true, cost_notes = true_total(st["usage"], st["cli_costs"], cfg["prices"], cfg["factors"])
    ceiling = killed[0] is not None and killed[0][0] in ("timeout", "interrupted") and not st["complete"]
    if ceiling: true = max(true, P.budget); notes.append("usage was not reported before the run was killed: the ledger holds the budget as a ceiling, not a measured cost")
    notes += cost_notes + factor_notes(st["usage"], st["cli_costs"], cfg["prices"], cfg["factors"], version)
    stream_cost = None
    if P.also_stream:
        streamed = streamed_usage(st["msgs"])
        stream_cost = true_total(streamed, {}, cfg["prices"], cfg["factors"])[0] if st["usage_events"] else None
        if st["assistant_events"] > st["usage_events"]:
            what = "no usage on any of its assistant events" if not st["usage_events"] else f"no usage on {st['assistant_events'] - st['usage_events']} of {st['assistant_events']} assistant events"
            notes.append(f"the stream carried {what}: the budget was kept by the CLI's flag ({ad['budget_flag']} {num(round(P.cli_budget, 4))}, factor {P.factor})"
                         + (" alone, not by the streamed stop" if not st["usage_events"] else " and by the streamed stop on the rest"))
        unp = unpriced_models(streamed, cfg["prices"])
        if unp: notes.append(f"the streamed stop could not count {', '.join(unp)}: no price in [prices]; only the CLI's flag at budget x factor stopped it, so that stop is approximate")
        if killed[0] and killed[0][0] == "budget" and not st["complete"]:
            notes.append("killed before the CLI's result: the true cost is the usage streamed up to the kill, input and cache tokens at the [prices] rates and output tokens as the stream reported them "
                         "(a placeholder), so what was spent is higher and the CLI's own figure was never reported")
    if st["errors"]: notes.append("CLI errors: " + "; ".join(st["errors"][:3]))
    if P.mode == "turn": notes.append("budget checked when each turn ends, not while a turn runs (--soft-budget)")
    if true > P.budget + 1e-9 and not ceiling: notes.append(f"over budget: true ${true:.4f} against budget ${P.budget:.2f}")
    status = "done"
    if killed[0]: status = killed[0][1] if killed[0][1].startswith("killed") else f"killed: {killed[0][1]}"
    elif st["failed"]: status = st["failed"]
    elif not st["complete"]: status = "result missing"
    elif proc.returncode != 0: status = f"exit {proc.returncode}"
    contract = {}
    if P.done_text is not None: contract["done"] = {"text": P.done_text, "found": P.done_text in text}
    if P.absent_text is not None: contract["absent"] = {"text": P.absent_text, "found": P.absent_text in text}
    unmet = [w for w, bad in (("done text missing", "done" in contract and not contract["done"]["found"]), ("absent text found", "absent" in contract and contract["absent"]["found"])) if bad]
    if status == "done" and unmet: status = "finished, contract unmet: " + ", ".join(unmet)
    with open(f"{run}/result.md", "w", encoding="utf-8") as f: f.write(text)
    out_path = None
    if P.out_path:
        if status == "done":
            out_path = P.out_path
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f: f.write(text)
        else: notes.append(f"--out {P.out_path} not written: the run is {status}")
    tin = sum(u["in"] + u["cache_write"] + u["cache_read"] for u in st["usage"].values()); tout = sum(u["out"] for u in st["usage"].values())
    cli = st["cli_total"]
    summary = {"status": status, "run": run, "dir": d, "reads": P.reads, "readonly": P.readonly, "adapter": P.adapter, "model": P.model, "effort": P.effort, "turns": st["turns"],
               "minutes": round(mins, 1), "budget": P.budget, "cli_cost": cli, "true_cost": true, "stream_cost": stream_cost, "true_cost_is_ceiling": ceiling, "tokens_in": tin, "tokens_out": tout,
               "key_source": st["key_source"], "session_id": st["session"], "denials": st["denials"], "exit": proc.returncode, "cli_version": version,
               "prices_read_on": str(cfg["prices"].get("read_on") or ""), "contract": contract, "out": out_path, "notes": notes}
    with open(f"{run}/summary.json", "w", encoding="utf-8") as f: json.dump(summary, f, indent=1)
    clean = lambda s: re.sub(r"[|\r\n]+", "/", str(s))
    tcost = f"true ${true:.4f}" + (" (ceiling, usage unreported)" if ceiling else "")
    ccost = f"cli ${cli:.4f}" if cli is not None else "cli $-"
    first = f"{P.adapter} {P.label} {P.effort or '-'} | {st['turns'] or '-'} turns | {mins:.1f} min | {ccost} | {tcost} | in {tin // 1000}k out {tout // 1000}k"
    new = not os.path.exists(P.ledger_path)
    with open(P.ledger_path, "a", encoding="utf-8") as f:
        if new: f.write(f"# {NAME} ledger: one line per run, appended when the run ends; the cap counts the 'true' column, the cost at the [prices] rates in config.toml\n")
        f.write(f"{t0.strftime('%Y-%m-%d %H:%M')} | {P.slug} | {d} | {first} | runs/{os.path.basename(run)} | {clean(status)}\n")
    total, _ = ledger_total(P.ledger_path)
    print(f"{NAME} {status} | {P.adapter} {P.label} {P.effort or '-'} | {st['turns'] or '-'} turns | {mins:.1f} min | {ccost} | {tcost} | in {tin // 1000}k out {tout // 1000}k"
          f" | paid by {st['key_source'] or '-'} | denials {len(st['denials'])} | ledger true total ${total:.2f} of cap ${P.cap:.0f}\nrun: {run}\nsession: {st['session']}"
          + (f"\nout: {out_path}" if out_path else ""), flush=True)
    if "done" in contract: print(f"done text {contract['done']['text']!r}: " + ("found" if contract["done"]["found"] else "MISSING"))
    if "absent" in contract: print(f"absent text {contract['absent']['text']!r}: " + ("FOUND" if contract["absent"]["found"] else "not in the result"))
    for t, i in st["denials"]: print(f"denied: {t} {i}")
    for n_ in notes: print(f"note: {n_}")
    print("---\n" + text)
    return 0 if status == "done" else 1


def parse_args(argv):
    a = argparse.ArgumentParser(prog=NAME, description="Run an agent CLI headless on a brief (stdin), inside a folder fence, under a dollar budget and a cap.")
    add = a.add_argument
    add("--dir", help="the run's folder: writable unless --readonly, the CLI works in it")
    add("--read", action="append", default=[], help="a folder the run may read, repeatable")
    add("--readonly", action="store_true", help="the run's folder is readable only")
    add("--adapter", help="which CLI adapter: claude, codex, or one declared in config.toml (default from config)")
    add("--model", help="model id or an adapter alias; needed for adapters that report tokens and no cost")
    add("--effort", help="reasoning effort, where the adapter supports it")
    add("--budget", type=float, help="true dollars this run may spend (default from config)")
    add("--turns", type=int, help="turn limit, where the CLI has one")
    add("--timeout", type=int, help="seconds before the run is killed (default from config)")
    add("--soft-budget", action="store_true", help="accept a budget checked only when each turn ends, for CLIs that report usage no sooner")
    add("--name", default="run", help="slug for the run's folder and ledger line")
    add("--out", help="write the result here when the run is done; relative to --dir, inside it")
    add("--resume", help="a session id to resume, where the adapter supports it")
    add("--done", help="text the result is expected to contain; reported, and a run without it is not 'done'")
    add("--absent", help="text the result must not contain; reported, and a run with it is not 'done'")
    add("--require-api-key", action=argparse.BooleanOptionalAction, default=None, help="check the CLI bills an API key and not a login (default on for claude)")
    add("--home", help=f"the tool's home: config.toml, cap, ledger.md, lock, runs/ (default ~/.config/{NAME})")
    add("--dry-run", action="store_true", help="print the command, the fence, the checks and the budget arithmetic; run nothing")
    add("--version", action="version", version=f"{NAME} {VERSION}")
    o = a.parse_args(argv)
    if not o.dir: a.error("--dir is required")
    return o


def main(argv=None):
    try:
        o = parse_args(argv)
        if sys.platform == "win32": raise Refused(f"{NAME} needs macOS sandbox-exec and refuses to run on Windows rather than run without a fence; see {ROADMAP}")
        home = derive_home()
        siwithin_home = real(o.home) if o.home else os.path.join(home, ".config", NAME)
        cfg, cfg_path, present, problems = load_config(siwithin_home)
        brief = sys.stdin.read() if (sys.stdin is not None and not sys.stdin.isatty()) else None
        now = datetime.datetime.now()
        P = make_plan(o, cfg, (cfg_path, present, problems), home, siwithin_home, brief, o.dry_run, now)
        if o.dry_run:
            show_plan(P)
            return 1 if any(lv == "refuse" for lv, _ in P.checks) else 0
        bad = [t for lv, t in P.checks if lv == "refuse"]
        if bad: raise Refused("; ".join(bad))
        os.makedirs(siwithin_home, mode=0o700, exist_ok=True)  # private: it holds briefs, events and the ledger
        os.makedirs(os.path.join(siwithin_home, "runs"), mode=0o700, exist_ok=True)
        lock = acquire_lock(os.path.join(siwithin_home, "lock"))
        # the plan is made again under the lock: the ledger and the run's folder name may have changed while another run held it
        P = make_plan(o, cfg, (cfg_path, present, problems), home, siwithin_home, brief, False, datetime.datetime.now())
        bad = [t for lv, t in P.checks if lv == "refuse"]
        if bad: raise Refused("; ".join(bad))
        lock.seek(0); lock.truncate(); lock.write(f"pid {os.getpid()} runs/{os.path.basename(P.run)} since {P.stamp}\n"); lock.flush()
        return execute(P, cfg)
    except Refused as x:
        print(f"refused: {x}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
