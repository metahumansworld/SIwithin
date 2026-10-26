#!/usr/bin/env python3
"""Smoke test: python3 tests/smoke.py. A temporary home, no agent CLI installed, nothing outside the temporary folder is touched.

Part 1 (macOS) runs siwithin.py --dry-run as a subprocess for each built-in adapter and asserts the command, the fence profile's deny and allow lines,
the refusal of forbidden folders, the cap arithmetic and the adapters' refusals. Part 2 checks the pieces: the TOML reader, the example config,
the money, the profile builder. The Linux group checks the Linux plan (bubblewrap's arguments, the preflight, the refusals, the walk's marker read) with
siwithin.PLATFORM forced to "linux" and the bubblewrap program replaced by a shim, so it runs on either platform. Part 3 drives a whole run in-process
against fake CLIs with the sandbox program replaced by a shim that only drops its arguments: once for macOS (on macOS) and once for Linux, with
siwithin.PLATFORM forced; it tests what the tool does around the CLI (streaming, kills, ledger, summary), not the fence itself. Part 4 (Linux, with a
working /usr/bin/bwrap only) runs fake CLIs inside the real fence; elsewhere it prints why it was skipped and counts nothing."""
import copy, hashlib, importlib.util, io, json, os, re, shlex, shutil, stat, subprocess, sys, tempfile, textwrap, time

sys.dont_write_bytecode = True  # importing siwithin.py must not leave a __pycache__ in the project
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec =importlib.util.spec_from_file_location("siwithin_under_test", os.path.join(ROOT, "siwithin.py"))
siwithin = importlib.util.module_from_spec(spec); spec.loader.exec_module(siwithin)

failures, count, show = [], 0, [False]


def check(cond, what):
    global count
    count += 1
    if not cond: failures.append(what); print(f"FAIL {what}")
    elif show[0]: print(f"ok   {what}")  # the key proxy's checks are named in the output as they pass


def group(name): print(f"-- {name}")


TMP = TMP_ROOT = os.path.realpath(tempfile.mkdtemp(prefix="siwithin-smoke-"))  # TMP moves into a folder of its own for each pass of Part 3; TMP_ROOT is what is removed at the end
HOME = os.path.join(TMP, "home"); os.makedirs(HOME)
FH = os.path.join(HOME, ".config", siwithin.NAME); os.makedirs(FH)
PROJ = os.path.join(HOME, "work", "proj"); os.makedirs(PROJ)
READ = os.path.join(HOME, "work", "ref"); os.makedirs(READ)
ENV = {"HOME": HOME, "PATH": "/usr/bin:/bin", "USER": "tester", "LANG": "C"}  # no CLI on this PATH
DARWIN = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
PLAT = "darwin"  # the pass of Part 3 in progress: "darwin" (the real platform, macOS only) or "linux" (siwithin.PLATFORM forced, the bubblewrap shim)
NO_FILTER = r"\((allow|deny) (file-[a-z-]+\*?|process-exec)\)"  # a sandbox-exec rule with nothing listed would apply to everything; read in Part 1 (macOS only) and in Part 2, which runs on both platforms


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


# ---- the key proxy: a fake upstream on loopback and a fake CLI that makes real requests through the proxy -----------------------------

TESTKEY = "test-key-smoke-only-7f3a9c1e5b2d4086"  # made up, not shaped like a real key
SONNET = (100 * 2.0 + 0 * 2.5 + 50 * 0.10 + 20 * 10.0) / 1e6  # one fake response priced at sonnet's [prices] rates: input 100, cache read 50, output 20
LOGSHIM = r'''
import glob, json, os, re, sys
a = sys.argv[1:]
with open(@CALLS@, "a") as f: f.write(json.dumps(a) + "\n")
if os.environ.get("LOG_SHIM_FAIL"): sys.stderr.write("log: the report is not readable here\n"); sys.exit(1)
assert a[:2] == ["show", "--start"] and a[a.index("--style") + 1] == "ndjson", a
mark = re.search(r'eventMessage CONTAINS "([^"]+)"', a[a.index("--predicate") + 1]).group(1)
assert mark.startswith("siwithin-net:"), mark
nth = sum(mark in l for l in open(@CALLS@).read().splitlines())  # which read of this run's mark this is
pids = [open(p).read().strip() for p in glob.glob(os.path.join(@EH@, ".config", "*", "runs", mark.split(":", 1)[1], "cli-pid.txt"))]
pid = int(pids[0]) if pids else 4242
def line(msg, image="/kernel"): print(json.dumps({"eventMessage": msg, "processImagePath": image}))
line(f"2 duplicate reports for Sandbox: pclaude({pid}) deny(1) network-outbound remote:*:443\n{mark}")
line(f"Sandbox: pclaude({pid}) deny(1) network-outbound /private/var/run/mDNSResponder\n{mark}")
line(f"Sandbox: curl({pid + 1}) deny(1) network-outbound remote:*:443\n{mark}")
line(f"Sandbox: pclaude({pid}) allow network-outbound remote:*:9\n{mark}")
if os.environ.get("LOG_SHIM_LATE") and nth >= 2: line(f"1 duplicate report for Sandbox: pclaude({pid}) deny(1) network-outbound remote:*:443\n{mark}")  # a coalesced line that lands after the first read
line("log run noninteractively, parent: 1 (zsh), args: '/usr/bin/log' 'show' '--predicate' 'eventMessage CONTAINS \"" + mark + "\"'", "/usr/bin/log")
print(json.dumps({"processImagePath": "/kernel"}))
print("")
'''
BWSHIM = r'''
import json, os, sys
# Stands in for /usr/bin/bwrap under siwithin.PLATFORM = "linux": it checks the arguments up to -- are bubblewrap's, as the tool builds them, and runs what follows --. There is no namespace here,
# so the bridge cannot be exercised: the shim checks that the command is the shell line that starts socat on the run's loopback port and strips it, and the fake CLI reaches the proxy's TCP port as on macOS.
a = sys.argv[1:]
with open(@CALLS@, "a") as f: f.write(json.dumps(a) + "\n")
assert "--" in a, a
i = a.index("--"); opts, cmd = a[:i], a[i + 1:]
j, unshare_net, sock, pre = 0, False, False, "--unshare-all" in opts
while j < len(opts):
    o = opts[j]
    if o in ("--bind", "--ro-bind", "--bind-try", "--ro-bind-try"):
        src, dst = opts[j + 1], opts[j + 2]
        assert src.startswith("/") and dst.startswith("/"), (o, src, dst)
        if o in ("--bind", "--ro-bind"): assert os.path.exists(src), f"bubblewrap refuses a source that is not there: {o} {src}"
        sock = sock or dst == @SOCK@
        j += 3
    elif o in ("--tmpfs", "--dev", "--proc"):
        assert opts[j + 1].startswith("/"), (o, opts[j + 1]); j += 2
    elif o.startswith("--unshare-") or o == "--die-with-parent":
        unshare_net = unshare_net or o == "--unshare-net"; j += 1
    else: sys.exit(f"bwrap shim: unknown option {o!r}")
if not pre: assert unshare_net == sock, f"--unshare-net is for network = proxy and goes with the proxy's socket bind: net {unshare_net}, socket {sock}"
if cmd[:2] == ["/bin/sh", "-c"] and @SOCAT@ in cmd[2]:
    assert sock and unshare_net and cmd[2].startswith(@SOCAT@ + " TCP-LISTEN:") and ",bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:" + @SOCK@ + " & exec" in cmd[2], cmd
    with open(@CALLS@, "a") as f: f.write(json.dumps({"bridge": cmd[2]}) + "\n")
    cmd = cmd[3:]
elif not pre: assert not (unshare_net and cmd[0] == "/bin/sh"), cmd
if cmd == ["/bin/true"] and not os.path.exists("/bin/true"): sys.exit(0)  # the preflight, where /bin/true is not (macOS)
os.execv(cmd[0], cmd)
'''
PCLAUDE = r'''
import json, os, subprocess, sys, time, urllib.error, urllib.request
a = sys.argv[1:]
if a == ["--version"]: print("2.1.296 (fake)"); sys.exit(0)
if a == ["auth", "status"]: print(json.dumps({"loggedIn": True, "authMethod": "api_key"})); sys.exit(0)
brief = sys.stdin.read()
run = os.path.dirname(os.environ["CLAUDE_CODE_TMPDIR"])
base, token = os.environ.get("ANTHROPIC_BASE_URL"), os.environ["ANTHROPIC_API_KEY"]
def ev(o): print(json.dumps(o), flush=True)
def note(name, text):
    with open(os.path.join(run, name), "a") as f: print(text, file=f)
with open(os.path.join(run, "cli-env.json"), "w") as f: json.dump(dict(os.environ), f)  # names and values, for the test to read
with open(os.path.join(run, "cli-pid.txt"), "w") as f: f.write(str(os.getpid()))  # the CLI's pid: the log shim puts it on its canned lines, so the figures' cli/others split is tested end to end
def call(path="/v1/messages", stream=True, key=None, model="claude-sonnet-5-5", header="x-api-key", first_byte=False):
    body = json.dumps({"model": model, "max_tokens": 16, "stream": stream, "messages": [{"role": "user", "content": "hi"}]}).encode()
    value = key or token
    req = urllib.request.Request(base + path, data=body, method="POST", headers={header: "Bearer " + value if header == "Authorization" else value,
                                 "content-type": "application/json", "anthropic-version": "2023-06-01"})
    out = {"path": path}
    try:
        r = urllib.request.urlopen(req, timeout=20)
        out["code"], out["rl"] = r.status, r.headers.get("anthropic-ratelimit-requests-remaining")
        piece = r.read1(65536)
        if first_byte: note("cli-first-byte.txt", repr(time.time()))  # when the first streamed bytes arrived
        out["body"] = (piece + r.read()).decode()
    except urllib.error.HTTPError as e: out["code"], out["body"] = e.code, e.read().decode()
    except Exception as e: out["code"] = type(e).__name__
    note("cli-codes.jsonl", json.dumps(out))
    return out["code"]
def assistant(mid, model="claude-sonnet-5-5"):
    ev({"type": "assistant", "message": {"id": mid, "model": model, "usage": {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 50, "output_tokens": 20}, "content": []}})
def result():
    ev({"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "result": "proxy run done", "total_cost_usd": 0.0008, "session_id": "sess-p", "permission_denials": [],
        "modelUsage": {"claude-sonnet-5-5": {"inputTokens": 200, "outputTokens": 40, "cacheReadInputTokens": 100, "cacheCreationInputTokens": 0, "webSearchRequests": 0, "costUSD": 0.00081}}})
NESTED = """
import json, os, urllib.request
run = os.path.dirname(os.environ["CLAUDE_CODE_TMPDIR"])
body = json.dumps({"model": "claude-opus-5-5", "max_tokens": 16, "stream": False, "messages": []}).encode()
req = urllib.request.Request(os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages", data=body, method="POST", headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "content-type": "application/json"})
with open(os.path.join(run, "nested.json"), "w") as f: json.dump({"code": urllib.request.urlopen(req, timeout=20).status}, f)
"""
LAUNCH = """
import subprocess, sys
# an orphan the walk cannot see: its environment is scrubbed down to the two variables it needs, it is in a session of its own, and this program, its parent, ends at once
subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2]], env={"ANTHROPIC_BASE_URL": sys.argv[3], "ANTHROPIC_API_KEY": sys.argv[4]}, start_new_session=True, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
"""
DETACHED = """
import json, os, sys, time, urllib.error, urllib.request
run = sys.argv[1]
body = json.dumps({"model": "claude-sonnet-5-5", "max_tokens": 16, "stream": False, "messages": []}).encode()
def code():
    req = urllib.request.Request(os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages", data=body, method="POST", headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "content-type": "application/json"})
    try: return str(urllib.request.urlopen(req, timeout=5).status)
    except urllib.error.HTTPError as e: return str(e.code)
    except Exception as e: return "ERR " + type(e).__name__
with open(os.path.join(run, "detached.txt"), "a") as f:
    print("pid", os.getpid(), file=f, flush=True)
    end, let_go, held = time.time() + 8, time.time() + 1.5, True
    while time.time() < end:
        if held and time.time() > let_go:  # the pipe to the runner is held until now, as an orphan holds it; then the runner can end, and this goes on asking
            os.dup2(os.open(os.devnull, os.O_RDWR), 1); held = False
        print(code(), file=f, flush=True); time.sleep(0.005)
"""
src = "ANTHROPIC_API_KEY"
if "MODE:helpersource" in brief: src = "apiKeyHelper"
ev({"type": "system", "subtype": "init", "apiKeySource": src, "session_id": "sess-p"})
if "MODE:wall" in brief:  # three requests; the budget is under the cost of two responses; the CLI would sleep on if it were not killed
    for _ in range(3): call()
    time.sleep(30)
elif "MODE:detached" in brief:  # one request spends the whole budget; then a process in a session of its own keeps requesting, and the CLI asks once more
    call()
    subprocess.run([sys.executable, "-c", LAUNCH, DETACHED, run, base, token], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # stdout is the runner's pipe, inherited
    for _ in range(200):
        if os.path.exists(os.path.join(run, "detached.txt")) and len(open(os.path.join(run, "detached.txt")).read().split("\n")) > 2: break
        time.sleep(0.05)
    call(); time.sleep(30)
elif "MODE:nested" in brief:  # the CLI's own request, and a second program's, as a run's own python3 would make it
    call(); subprocess.run([sys.executable, "-c", NESTED]); result()
elif "MODE:paths" in brief:  # paths off the list and on it, and two that only look like entries
    for p in ("/v1/complete", "/v1/messages/count_tokens", "/v1/messages/count_tokens/", "/v1/messages/batches", "/v1/messages/../complete", "/v1/messages;x=1", "/v1/messages?beta=true"): call(p, stream=False)
    result()
elif "MODE:sleep" in brief: call(); time.sleep(30)
elif "MODE:bearer" in brief: call(header="Authorization"); result()
elif "MODE:envdump" in brief: result()
elif "MODE:helpersource" in brief: time.sleep(30)
else:
    call(first_byte=True); assistant("m1"); call(stream=False); assistant("m2")
    call("/v1/messages/count_tokens", stream=False); call(key="siwithin-not-the-token"); result()
'''


# ---- the kill walk: a stand-in for ps where ps cannot be run, and a fake CLI that leaves processes behind -------------------------------

FAKE_PS = r'''
import ctypes, ctypes.util, os, sys
# A stand-in for /bin/ps, used only where the real one cannot be run (a launcher that refuses to exec it): the same two outputs the walk reads, taken from the real process table
# through libproc and the procargs sysctl. `ps -A -o pid=,ppid=,stat=` and `ps -E -A -ww` (the command and then the environment, as ps -E prints them).
lib, libc = ctypes.CDLL(ctypes.util.find_library("proc")), ctypes.CDLL(None)
class BSD(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint32), ("status", ctypes.c_uint32), ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
                ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32), ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32), ("svgid", ctypes.c_uint32), ("rfu", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32), ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32), ("pjobc", ctypes.c_uint32), ("tdev", ctypes.c_uint32),
                ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32), ("tv", ctypes.c_uint64), ("tvu", ctypes.c_uint64)]
n = lib.proc_listpids(1, 0, None, 0)
buf = (ctypes.c_int * (n // 4 + 256))()
pids = sorted(buf[i] for i in range(lib.proc_listpids(1, 0, buf, ctypes.sizeof(buf)) // 4) if buf[i] > 0)
def info(pid):
    b = BSD()
    return b if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(b), ctypes.sizeof(b)) == ctypes.sizeof(b) else None
def procargs(pid):
    mib, size = (ctypes.c_int * 3)(1, 49, pid), ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or not size.value: return None
    out = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, out, ctypes.byref(size), None, 0) != 0: return None
    raw = out.raw[:size.value]; argc = int.from_bytes(raw[:4], "little"); parts = raw[4:].split(b"\0"); i = 1
    while i < len(parts) and parts[i] == b"": i += 1
    return [x.decode("utf-8", "replace") for x in parts[i:i + argc] + [p for p in parts[i + argc:] if p]]
a = sys.argv[1:]
if a == ["-A", "-o", "pid=,ppid=,stat="]:
    for pid in pids:
        b = info(pid)
        if b: print(f"{pid:5d} {b.ppid:5d} {'Z' if b.status == 5 else 'S'}")
elif a == ["-E", "-A", "-ww"]:
    print("  PID TTY           TIME CMD")
    for pid in pids:
        b = info(pid)
        if b: print(f"{pid:5d} ??         0:00.00 " + " ".join(procargs(pid) or [b.comm.decode()]))
elif a == ["-A", "-ww", "-o", "pid=,tty=,time=,args=", "e"]:  # the Linux walk's read: the same rows without the header, in procps's shape (measured: pid, tty, cpu time, command, then the environment)
    for pid in pids:
        b = info(pid)
        if b: print(f"{pid:5d} ?        00:00:00 " + " ".join(procargs(pid) or [b.comm.decode()]))
else: sys.exit(64)
'''

WCLAUDE = r'''
import json, os, subprocess, sys, time
a = sys.argv[1:]
if a == ["--version"]: print("2.1.296 (fake)"); sys.exit(0)
if a == ["auth", "status"]: print(json.dumps({"loggedIn": True, "authMethod": "api_key"})); sys.exit(0)
brief = sys.stdin.read()
run = os.path.dirname(os.environ["CLAUDE_CODE_TMPDIR"])
def ev(o): print(json.dumps(o), flush=True)
ev({"type": "system", "subtype": "init", "apiKeySource": "ANTHROPIC_API_KEY", "session_id": "sess-w"})
HB = """
import os, sys, time
with open(os.path.join(sys.argv[1], "hb.txt"), "a") as f:
    print("pid", os.getpid(), file=f, flush=True)
    end = time.time() + 40
    while time.time() < end: print(repr(time.time()), file=f, flush=True); time.sleep(0.05)
"""
HOLD = """
import os, sys, time
with open(os.path.join(sys.argv[1], "hold.txt"), "a") as f: print("pid", os.getpid(), file=f, flush=True)
time.sleep(40)
"""
def result():
    ev({"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "result": "walk run done", "total_cost_usd": 0.01, "session_id": "sess-w",
        "modelUsage": {"claude-sonnet-5-5": {"inputTokens": 1000, "outputTokens": 100, "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0, "webSearchRequests": 0, "costUSD": 0.01}}, "permission_denials": []})
def heartbeat():  # a program in a session of its own, writing the time to hb.txt every 50 ms, with no pipe of the runner's
    subprocess.Popen([sys.executable, "-c", HB, run], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(200):
        if os.path.exists(os.path.join(run, "hb.txt")) and len(open(os.path.join(run, "hb.txt")).read().split("\n")) > 3: break
        time.sleep(0.02)
def hold(env):  # a program in a session of its own that keeps the runner's stdout pipe open
    subprocess.Popen([sys.executable, "-c", HOLD, run], start_new_session=True, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **({"env": {}} if env == "scrubbed" else {}))
    for _ in range(200):
        if os.path.exists(os.path.join(run, "hold.txt")): break
        time.sleep(0.02)
def orphan():  # the heartbeat launched by a program that exits at once: by the first look its parent is gone and it is in no one's ancestry, as a task's python3 -c "Popen(...)" leaves it
    subprocess.run([sys.executable, "-c", "import subprocess, sys; subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)", HB, run], stdin=subprocess.DEVNULL)
    for _ in range(200):
        if os.path.exists(os.path.join(run, "hb.txt")) and len(open(os.path.join(run, "hb.txt")).read().split("\n")) > 3: break
        time.sleep(0.02)
def msg(mid, **u):
    usage = {"input_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 8}; usage.update(u)
    ev({"type": "assistant", "message": {"id": mid, "model": "claude-sonnet-5-5", "usage": usage, "content": []}})
if "MODE:budget" in brief:  # a detached program, then usage past the budget of $0.50 ($0.25, then $0.30 more), then the CLI sleeps on
    heartbeat(); msg("m1", cache_creation_input_tokens=100000); msg("m2", input_tokens=100000, cache_read_input_tokens=1000000); time.sleep(60)
elif "MODE:exit" in brief: heartbeat(); result()  # a detached program, a result, and the CLI exits on its own
elif "MODE:pipe" in brief: hold("inherited"); result()  # a detached program holding the runner's pipe, its environment as the run's
elif "MODE:scrub" in brief: hold("scrubbed"); result()  # the same, its environment scrubbed: the walk cannot know it
elif "MODE:orphan" in brief: orphan(); time.sleep(60)  # the program's launcher has exited; the CLI sleeps on and the timer stops it, as the live outlive brief ended
else: result()
'''


PS_PATH = siwithin.PS  # the real ps, before any pass stands the stand-in in


def ps_works(path):
    try: r = subprocess.run([path, "-A", "-o", "pid=,ppid=,stat="], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError): return False
    return r.returncode == 0 and str(os.getpid()) in r.stdout.split()


def proxy_tests(whole, last_run, ledger, EH, ED, BIN):
    import http.server, signal, socket, threading, urllib.error, urllib.request

    def sse(name, obj): return f"event: {name}\ndata: {json.dumps(obj)}\n\n".encode()

    class UpHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a): pass

        def put(self, data, label):  # one chunk, flushed, and the time it was written
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data)); self.wfile.flush(); self.rec["writes"].append((label, time.time()))

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.rec = {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body, "writes": []}
            self.server.recs.append(self.rec)
            req, path = json.loads(body or b"{}"), self.path.split("?")[0]
            usage = {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 50, "output_tokens": 20}
            self.send_response(200)
            self.send_header("anthropic-ratelimit-requests-remaining", "99")
            if path.endswith("/count_tokens") or req.get("stream") is False:
                out = json.dumps({"input_tokens": 5} if path.endswith("/count_tokens") else {"id": "msg_j", "type": "message", "model": req.get("model"), "usage": usage}).encode()
                self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers()
                self.wfile.write(out); self.wfile.flush(); self.rec["writes"].append(("json", time.time()))
            else:
                self.send_header("Content-Type", "text/event-stream"); self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
                self.put(sse("message_start", {"type": "message_start", "message": {"id": "msg_s", "type": "message", "role": "assistant", "model": req.get("model"), "content": [],
                                                                                    "usage": dict(usage, output_tokens=1)}}), "start")
                time.sleep(0.3)  # the proxy must pass the first bytes on while the rest has not been written yet
                self.put(sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hi"}})
                         + sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 20}})
                         + sse("message_stop", {"type": "message_stop"}), "rest")
                self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()

    class Up(http.server.ThreadingHTTPServer): daemon_threads = True

    try:
        UP = Up(("127.0.0.1", 0), UpHandler)
    except OSError as x:
        print(f"SKIPPED key proxy checks: no loopback server can be bound here ({x}); the tests are written, run them where one can")
        return
    UP.recs = []
    threading.Thread(target=UP.serve_forever, daemon=True).start()
    group("key proxy")
    pids = []
    show[0] = True
    try:
        proxy_checks(whole, last_run, ledger, EH, ED, BIN, UP, pids)
    finally:
        show[0] = False
        UP.shutdown(); UP.server_close()
        for pid in pids:
            try: os.kill(pid, signal.SIGKILL)  # the detached child of the test is killed whatever happened
            except OSError: pass


def proxy_checks(whole, last_run, ledger, EH, ED, BIN, UP, pids):
    import signal, socket, threading
    write(os.path.join(BIN, "pclaude"), f"#!{sys.executable}\n" + PCLAUDE); os.chmod(os.path.join(BIN, "pclaude"), 0o755)
    UPSTREAM = f"http://127.0.0.1:{UP.server_address[1]}"
    KEY = {"ANTHROPIC_API_KEY": TESTKEY}  # the runner's own environment: the key lives here and nowhere else

    def mkhome(tag, adapter='bin = "pclaude"\n', auth_extra=""):
        h = os.path.join(EH, ".config", "siwithin-" + tag); os.makedirs(h)
        write(os.path.join(h, "cap"), "100")
        write(os.path.join(h, "config.toml"), f'[adapters.claude]\n{adapter}\n[auth]\nupstream = "{UPSTREAM}"\n{auth_extra}')
        return h

    def fresh(home, brief, args=(), env=KEY):
        UP.recs.clear()
        rc, out, err = whole(["--home", home, "--dir", ED] + list(args), brief=brief, extra_env=env)
        r, s = last_run(home)
        return rc, out, err, r, s, list(UP.recs)

    def jl(path): return [json.loads(l) for l in open(path).read().split("\n") if l]

    PF = mkhome("proxy")

    # ---- the network wall's figures: fence.sb names the proxy's real port, and the kernel's report (the log shim's canned lines here, under the run's mark) is counted in summary.json
    NF = mkhome("net")
    if PLAT == "darwin":
        calls_path = os.path.join(os.path.dirname(BIN), "log-calls.txt")
        rc, out, err, r, s, recs = fresh(NF, "a plain run under the network wall\n")
        cmd_txt = open(os.path.join(r, "command.txt")).read(); port = int(re.search(r"^auth: proxy 127\.0\.0\.1:(\d+)$", cmd_txt, re.M).group(1)); sb = open(os.path.join(r, "fence.sb")).read()
        mark = f"siwithin-net:{os.path.basename(r)}"; pid = int(open(os.path.join(r, "cli-pid.txt")).read()); nw = s["network"]
        check(rc == 0 and f'(deny network* (with message "{mark}"))\n(allow network-outbound (remote ip "localhost:{port}"))' in sb and "@PROXY_PORT@" not in sb and "network: proxy\n" in cmd_txt,
              f"network 12: the run's fence.sb refuses every socket under the run's own mark and allows the proxy's real port {port}; command.txt records the mode")
        mine = [json.loads(l) for l in open(calls_path).read().splitlines() if mark in l]
        check(len(mine) == 2 and all(m[:2] == ["show", "--start"] and m[2] <= m[4] and m[-2] == "--predicate" and m[-1] == f'eventMessage CONTAINS "{mark}"' for m in mine) and mine[0][4] <= mine[1][4],
              f"network 12b: the kernel's report was read twice, by the run's mark, between the run's times, the second read's end no earlier than the first's: {mine}")
        check(nw["mode"] == "proxy" and nw["mark"] == mark and (nw["refused"], nw["reported"], nw["cli"], nw["others"], nw["unparsed"], nw["late"]) == (4, 1, 4, 1, 0, 0) and nw["processes"] == {f"pclaude({pid})": 4, f"curl({pid + 1})": 1}
              and nw["targets"]["deny network-outbound remote:*:443"] == 3 and not s["notes"], f"network 12c: summary.json's network figures: the refusals counted, the CLI's own pid {pid} told from the others': {nw}")
        check("\nnetwork: proxy, refused 4 (cli 4, others 1): deny network-outbound remote:*:443 x3, allow network-outbound remote:*:9 x1, deny network-outbound /private/var/run/mDNSResponder x1\n" in out, f"network 12d: the line is printed after the summary line: {out[:400]!r}")
        rc, out, err, r, s, recs = fresh(NF, "a plain run, the network reported\n", ["--network", "report"])
        mark = f"siwithin-net:{os.path.basename(r)}"; sb = open(os.path.join(r, "fence.sb")).read(); nw = s["network"]
        check(rc == 0 and f'(allow (with report) network* (with message "{mark}"))' in sb and "(deny network" not in sb and nw["mode"] == "report" and nw["reported"] == 1 and "network: report\n" in open(os.path.join(r, "command.txt")).read()
              and "\nnetwork: report, reported 1 (cli 4, others 1): " in out, f"network 14: --network report on a proxy home: the report rule in fence.sb, the figures and the line say report: {nw}")
        rc, out, err, r, s, recs = fresh(NF, "a plain run, the report unreadable\n", env=dict(KEY, LOG_SHIM_FAIL="1"))
        nw = s["network"]
        check(rc == 0 and s["status"] == "done" and nw["refused"] == 0 and nw["mark"] == f"siwithin-net:{os.path.basename(r)}" and "show exit 1: log: the report is not readable here" in nw["note"]
              and sum(n.startswith("network: the kernel's report could not be read (") and n.endswith("the fence's refusals, if any, are uncounted") for n in s["notes"]) == 1
              and "\nnetwork: proxy, refused 0 (cli 0, others 0); the kernel's report could not be read: " in out, f"network 15: when the report cannot be read the run still ends done, the figures are zero with the reason, and the note says the refusals are uncounted: {nw['note']!r}")
        rc, out, err, r, s, recs = fresh(NF, "a plain run, a line landing late\n", env=dict(KEY, LOG_SHIM_LATE="1"))
        nw = s["network"]; pid = int(open(os.path.join(r, "cli-pid.txt")).read())
        check(rc == 0 and s["status"] == "done" and (nw["refused"], nw["late"]) == (5, 1) and nw["targets"]["deny network-outbound remote:*:443"] == 4 and nw["processes"][f"pclaude({pid})"] == 5
              and s["notes"] == ["network: 1 of the kernel's lines landed between the first read of its report and the second, 0s apart; the second read's figures stand"]
              and "\nnetwork: proxy, refused 5 (cli 5, others 1): deny network-outbound remote:*:443 x4, " in out, f"network 16: a coalesced line that lands between the two reads is counted by the second and noted: {nw} {s['notes']}")
    else:  # Linux: bubblewrap's arguments in fence.sb, the bridge in the command, and no kernel report to read
        rc, out, err, r, s, recs = fresh(NF, "a plain run under the network wall\n")
        cmd_txt = open(os.path.join(r, "command.txt")).read(); port = int(re.search(r"^auth: proxy 127\.0\.0\.1:(\d+)$", cmd_txt, re.M).group(1)); sb = open(os.path.join(r, "fence.sb")).read().split("\n")
        argv = shlex.split(cmd_txt.split("\n", 1)[0]); nw = s["network"]
        check(rc == 0 and sb[0] == siwithin.FENCE_HEAD and "--unshare-net" in sb and ["--bind", os.path.join(r, "proxy.sock"), siwithin.PROXY_SOCK] == sb[sb.index("--bind", sb.index("--unshare-net")):][:3]
              and "network: proxy\n" in cmd_txt and not os.path.exists(os.path.join(r, "proxy.sock")),
              f"network 12: Linux: fence.sb is bubblewrap's arguments, one to a line under the first line, with --unshare-net and the proxy's Unix socket bound to its fixed path; the socket file is gone after the run")
        i = argv.index("--")
        check(argv[0] == os.path.join(BIN, "bwrap-shim") and argv[i + 1:i + 3] == ["/bin/sh", "-c"] and argv[i + 3] == f'{os.path.join(BIN, "socat-dummy")} TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:{siwithin.PROXY_SOCK} & exec "$0" "$@"'
              and argv[i + 4].endswith("/pclaude") and argv[i + 5] == "-p" and argv[1:i] == sb[1:-1],
              f"network 12b: Linux: command.txt is the fence program, its arguments, --, then the shell line that starts socat on the proxy's port {port} and execs the CLI: {argv[i + 1:i + 5]}")
        calls = [json.loads(l) for l in open(os.path.join(os.path.dirname(BIN), "bwrap-calls.txt")).read().splitlines()]
        bridges = [c["bridge"] for c in calls if isinstance(c, dict)]
        check(bridges.count(argv[i + 3]) == 3 and all(f"TCP-LISTEN:{port}," in b for b in bridges if b == argv[i + 3]),
              f"network 12c: Linux: the shim saw the same bridge line three times for the run, on the version probe, the auth probe and the launch: {bridges.count(argv[i + 3])}")
        check(nw == {"mode": "proxy", "mark": None, "refused": 0, "reported": 0, "targets": {}, "processes": {}, "cli": 0, "others": 0, "unparsed": 0, "late": 0, "note": siwithin.LINUX_NET_NOTE} and not s["notes"]
              and f"\nnetwork: proxy; {siwithin.LINUX_NET_NOTE}\n" in out and not os.path.exists(os.path.join(os.path.dirname(BIN), "log-calls.txt")),
              f"network 12d: Linux: summary.json's network says proxy, nothing refused or reported, and why; the line is printed; the kernel's log was not read: {nw}")
        n_runs = len(os.listdir(os.path.join(NF, "runs")))
        rc, out, err, r, s, recs = fresh(NF, "a plain run, the network reported\n", ["--network", "report"])
        check(rc == 1 and "network: report reads the macOS kernel's log, which Linux has no counterpart of; use proxy (the wall) or open" in err and len(os.listdir(os.path.join(NF, "runs"))) == n_runs,
              f"network 14: Linux: --network report is refused before launch, naming the way out: {err.strip()[:130]}")
        rc, out, err, r, s, recs = fresh(NF, "a plain run, the network open\n", ["--network", "open"])
        sb = open(os.path.join(r, "fence.sb")).read().split("\n"); cmd_txt = open(os.path.join(r, "command.txt")).read(); argv = shlex.split(cmd_txt.split("\n", 1)[0])
        check(rc == 0 and s["status"] == "done" and "--unshare-net" not in sb and not any(x.endswith("proxy.sock") for x in sb) and "network: open\n" in cmd_txt and argv[argv.index("--") + 1].endswith("/pclaude") and "TCP-LISTEN" not in cmd_txt
              and s["network"]["mode"] == "open" and "\nnetwork: open, unreported\n" in out and len(recs) == 3 and not os.path.exists(os.path.join(r, "proxy.sock")),
              "network 15: Linux: --network open: no --unshare-net, no socket bind, no bridge; the CLI reaches the proxy's TCP port and the requests arrive")
        sd = os.path.join(BIN, "socat-dummy"); os.remove(sd); n_runs = len(os.listdir(os.path.join(NF, "runs")))
        try:
            rc, out, err, r, s, recs = fresh(NF, "a plain run, no socat\n")
            rc_o, out_o, err_o, r_o, s_o, recs_o = fresh(NF, "a plain run, no socat, the network open\n", ["--network", "open"])
        finally: write(sd, "#!/bin/sh\nexit 0\n"); os.chmod(sd, 0o755)
        check(rc == 1 and "socat-dummy not found: network = proxy bridges the run's loopback port to the key proxy with socat; install socat (apt install socat; dnf install socat)" in err and len(os.listdir(os.path.join(NF, "runs"))) == n_runs + 1 and rc_o == 0 and s_o["status"] == "done",
              f"network 16: Linux: network = proxy without socat is refused, naming the package and leaving no run; --network open does not need it: {err.strip()[:120]}")
    TAIL = re.compile(r" \| receipt ([0-9a-f]{64})$")

    # ---- the plain run: three requests that pass, one with a wrong token
    t0 = time.time()
    rc, out, err, r, s, recs = fresh(PF, "MODE:basic")
    codes = jl(os.path.join(r, "cli-codes.jsonl")); cli_env = json.load(open(os.path.join(r, "cli-env.json"))); plog = jl(os.path.join(r, "proxy.jsonl"))
    token, cmd_txt = cli_env["ANTHROPIC_API_KEY"], open(os.path.join(r, "command.txt")).read()
    port = int(re.search(r"^auth: proxy 127\.0\.0\.1:(\d+)$", cmd_txt, re.M).group(1))
    check(rc == 0 and s["status"] == "done", f"proxy run: rc {rc}, {s.get('status')}, {err}")
    check(len(recs) == 3 and all(x["headers"].get("x-api-key") == TESTKEY and token not in json.dumps(x["headers"]) and "authorization" not in x["headers"] for x in recs),
          f"proxy 1: the upstream saw x-api-key equal to the runner's key on each request, never the token: {[x['headers'].get('x-api-key') for x in recs]}")
    check(all(x["headers"].get("host") == UPSTREAM[7:] and x["headers"].get("anthropic-version") == "2023-06-01" and x["headers"].get("accept-encoding") == "identity" and int(x["headers"]["content-length"]) == len(x["body"])
              and "transfer-encoding" not in x["headers"] and "connection" not in x["headers"] for x in recs) and json.loads(recs[0]["body"])["model"] == "claude-sonnet-5-5",
          "proxy 1b: Host is the upstream's, the other headers and the body are the run's, no hop-by-hop headers")
    files = [os.path.join(dp, f) for dp, _, fs in os.walk(r) for f in fs]
    ledger_text = open(os.path.join(PF, "ledger.md")).read()
    check(not [f for f in files if TESTKEY.encode() in open(f, "rb").read()] and TESTKEY not in ledger_text + out + err and TESTKEY not in "".join(cli_env.values())
          and re.fullmatch(r"siwithin-[A-Za-z0-9_-]{32}", token) and cli_env["ANTHROPIC_BASE_URL"] == f"http://127.0.0.1:{port}",
          f"proxy 2: the runner's key is in no file of the run, nor the ledger, nor the output, nor the CLI's environment; that holds a token and the proxy's address ({token[:12]}…, port {port})")
    check(all(token not in open(os.path.join(r, n)).read() for n in ("proxy.jsonl", "summary.json", "command.txt", "events.jsonl", "stderr.txt")) and token not in ledger_text + out + err,
          "proxy 2b: the token is in no file the runner wrote either")
    check("ANTHROPIC_BASE_URL" in cmd_txt.split("\n")[1] and "ANTHROPIC_API_KEY" in cmd_txt.split("\n")[1], "proxy 2c: command.txt lists the two names")
    wrong = [c for c in codes if c["code"] == 401]
    check(len(wrong) == 1 and json.loads(wrong[0]["body"]) == {"type": "error", "error": {"type": "authentication_error", "message": "SIwithin: not this run's token"}}
          and [x for x in plog if x["status"] == 401] and [x for x in plog if x["status"] == 401][0]["refused"] == "auth" and [x for x in plog if x["status"] == 401][0]["cost"] is None
          and not any("siwithin-not-the-token" in json.dumps(x["headers"]) for x in recs) and len(recs) == 3,
          "proxy 3: a wrong token gets 401 in the API's error shape, is logged refused and unpriced, and is not forwarded")
    priced = [x for x in plog if x["path"] == "/v1/messages" and x["status"] == 200]
    check(abs(s["proxy_cost"] - 2 * SONNET) < 1e-9 and s["true_cost"] == round(2 * SONNET, 4) and f"true ${s['true_cost']:.4f} |" in ledger(PF)[-1] and f"true ${s['true_cost']:.4f}" in out
          and s["proxy_requests"] == 3 and s["proxy_refused"] == 1 and s["stream_cost"] == round(2 * SONNET, 4) and not s["notes"]
          and [x["cost"] for x in priced] == [round(SONNET, 6)] * 2 and priced[1]["total"] == round(2 * SONNET, 6)
          and all(x["usage"] == {"in": 100, "cache_write": 0, "cache_read": 50, "out": 20, "searches": 0} for x in priced) and not s["true_cost_is_ceiling"],
          f"proxy 4: the proxy total is the usage priced at [prices] ({s['proxy_cost']}); the ledger line's true $ and the summary line carry it; summary.json has the three new fields; the streamed cost agrees")
    check([x["usage"] for x in plog if x["path"].endswith("count_tokens")] == [None] and [json.loads(c["body"]) for c in codes if c["path"].endswith("count_tokens")] == [{"input_tokens": 5}]
          and all(c["rl"] == "99" for c in codes if c["code"] == 200) and "message_stop" in [c for c in codes if c["code"] == 200][0]["body"]
          and json.loads([c for c in codes if c["code"] == 200][1]["body"])["usage"]["output_tokens"] == 20,
          "proxy 4b: count_tokens is forwarded and logged with usage null; responses and their headers reach the CLI intact, streamed and JSON")
    streamed = [x for x in recs if json.loads(x["body"]).get("stream") is True][0]
    first = float(open(os.path.join(r, "cli-first-byte.txt")).read().split()[0]); second = [w for w in streamed["writes"] if w[0] == "rest"][0][1]
    check(first < second and second - first > 0.1, f"proxy 8: streaming: the CLI's first byte arrived {second - first:.2f}s before the upstream's second write")

    # ---- receipts
    rec = json.load(open(os.path.join(r, "receipt.json")))
    names = sorted(siwithin.RECEIPT_FILES + ("proxy.jsonl",))
    check(sorted(rec["files"]) == names, "proxy 9a: the receipt lists proxy.jsonl besides the seven files")
    check(rec["files"]["proxy.jsonl"] == siwithin.sha256_file(os.path.join(r, "proxy.jsonl")) and TAIL.search(ledger(PF)[-1]).group(1) == siwithin.sha256_file(os.path.join(r, "receipt.json")),
          "proxy 9b: the hash of proxy.jsonl in the receipt is the file's")
    rc2, out2, _ = tool_cli(["--verify", "--home", PF]); rc3, out3, _ = tool_cli(["--verify", r])
    check(rc2 == 0 and out2.strip().endswith("1 receipts ok, 0 failed, 0 lines without a receipt") and rc3 == 0 and f"{len(names)} files match the receipt" in out3, f"proxy 9c: --verify passes on the home and on the run folder: {out2.strip()!r} {out3.strip()!r}")
    CP = os.path.join(TMP, "copy-proxy"); shutil.copytree(PF, CP)
    cp = os.path.join(CP, "runs", os.path.basename(r), "proxy.jsonl"); b = bytearray(open(cp, "rb").read()); b[5] ^= 1; open(cp, "wb").write(bytes(b))
    rc4, out4, _ = tool_cli(["--verify", "--home", CP])
    os.remove(cp)
    rc5, out5, _ = tool_cli(["--verify", "--home", CP])
    check(rc4 == 1 and "proxy.jsonl differs from the receipt" in out4 and rc5 == 1 and "proxy.jsonl is missing" in out5, f"proxy 9d: a changed proxy.jsonl fails --verify, and so does a missing one: {out4.strip()!r}")

    # ---- the budget wall: under the cost of two responses; the third request is refused and the run is killed
    t1 = time.time()
    rc, out, err, r, s, recs = fresh(PF, "MODE:wall", ["--budget", "0.0006", "--timeout", "20"])
    plog = jl(os.path.join(r, "proxy.jsonl")); codes = jl(os.path.join(r, "cli-codes.jsonl"))
    refusals = [x for x in plog if x["refused"] == "budget"]
    check(rc == 1 and s["status"] == "killed: budget $0.0006 reached at $0.0008 true" and time.time() - t1 < 15
          and [x["status"] for x in plog] == [200, 200, 402] and len(refusals) == 1 and refusals[0]["usage"] is None and refusals[0]["cost"] is None
          and len([x for x in recs if x["path"] == "/v1/messages"]) == 2 and [c["code"] for c in codes[:2]] == [200, 200] and all(c["code"] == 402 for c in codes[2:])
          and abs(s["true_cost"] - 0.0008) < 1e-9 and abs(s["proxy_cost"] - 2 * SONNET) < 1e-9 and s["proxy_refused"] == 1 and "true $0.0008 |" in ledger(PF)[-1],
          f"proxy 5: the budget wall: the third request got 402 and was not forwarded, the run was killed, true $ is the two responses ({s['status']}, {[x['status'] for x in plog]}, {codes[2:]})")

    # ---- nested spend: a second program the CLI starts, with the token
    rc, out, err, r, s, recs = fresh(PF, "MODE:nested")
    plog = jl(os.path.join(r, "proxy.jsonl")); opus = (100 * 4.0 + 50 * 0.20 + 20 * 20.0) / 1e6
    check(rc == 0 and json.load(open(os.path.join(r, "nested.json")))["code"] == 200 and [x["model"] for x in plog] == ["claude-sonnet-5-5", "claude-opus-5-5"]
          and abs(s["proxy_cost"] - (SONNET + opus)) < 1e-9 and s["true_cost"] == round(SONNET + opus, 4) and f"true ${s['true_cost']:.4f} |" in ledger(PF)[-1] and len(recs) == 2,
          f"proxy 6: nested spend: the second program's request is in the proxy total and in true $ ({s['proxy_cost']}, {s['true_cost']})")

    # ---- a process in a session of its own: 402 while the runner lives, no connection after
    rc, out, err, r, s, recs = fresh(PF, "MODE:detached", ["--budget", "0.0003", "--timeout", "20"])
    lines = open(os.path.join(r, "detached.txt")).read().split("\n"); pid = int(lines[0].split()[1]); pids.append(pid)
    base_url = json.load(open(os.path.join(r, "cli-env.json")))["ANTHROPIC_BASE_URL"]
    time.sleep(0.5)
    seen = [l for l in open(os.path.join(r, "detached.txt")).read().split("\n")[1:] if l]
    errs = [i for i, c in enumerate(seen) if c.startswith("ERR")]
    refused_at_end = None
    try: socket.create_connection(("127.0.0.1", int(base_url.rsplit(":", 1)[1])), timeout=2).close()
    except OSError as x: refused_at_end = type(x).__name__
    check(rc == 1 and s["status"] == "killed: budget $0.0003 reached at $0.0004 true" and seen and seen[0] == "402" and errs and errs[0] >= 10 and all(c == "402" for c in seen[:errs[0]]) and all(c.startswith("ERR") for c in seen[errs[0]:])
          and "200" not in seen and refused_at_end == "ConnectionRefusedError" and len(recs) == 1 and s["true_cost"] == round(SONNET, 4) and s["proxy_refused"] >= 10,
          f"proxy 7: a detached child got 402 for each request while the runner lived ({seen[:errs[0]].count('402') if errs else '-'} of them) and could not connect after: {sorted(set(seen))}, then {refused_at_end}")
    try: os.kill(pid, signal.SIGKILL)
    except OSError: pass

    # ---- the path allowlist: only [auth] paths are forwarded with the real key
    rc, out, err, r, s, recs = fresh(PF, "MODE:paths")
    codes = jl(os.path.join(r, "cli-codes.jsonl")); plog = jl(os.path.join(r, "proxy.jsonl")); gone = [x for x in plog if x["refused"] == "path"]
    check(rc == 0 and [c["code"] for c in codes] == [403, 200, 200, 403, 403, 403, 200] and json.loads(codes[0]["body"]) == {"type": "error", "error": {"type": "permission_error", "message": "SIwithin: path /v1/complete is not on [auth] paths"}},
          f"paths 1: /v1/complete gets 403 in the API's error shape; count_tokens, with a trailing slash too, and /v1/messages?beta=true pass; batches, a ../ path and a ;x path are refused: {[c['code'] for c in codes]}")
    check([x["path"] for x in recs] == ["/v1/messages/count_tokens", "/v1/messages/count_tokens/", "/v1/messages?beta=true"] and not any("complete" in x["path"] or "batches" in x["path"] for x in recs)
          and not any(TESTKEY in json.dumps(x["headers"]) for x in recs if "complete" in x["path"]),
          f"paths 2: the fake upstream never saw a path that is not on the list: {[x['path'] for x in recs]}")
    check([x["path"] for x in gone] == ["/v1/complete", "/v1/messages/batches", "/v1/messages/../complete", "/v1/messages;x=1"] and all(x["status"] == 403 and x["cost"] is None and x["usage"] is None for x in gone)
          and s["proxy_refused"] == 4 and s["proxy_requests"] == 3, f"paths 3: each refusal is logged with \"refused\": \"path\", unpriced: {[x['path'] for x in gone]}, refused {s['proxy_refused']}")
    PX = mkhome("proxy-paths", auth_extra='paths = ["/v1/complete/"]\n')
    rc, out, err, r, s, recs = fresh(PX, "MODE:paths")
    codes = jl(os.path.join(r, "cli-codes.jsonl"))
    check(rc == 0 and [c["code"] for c in codes] == [200, 403, 403, 403, 403, 403, 403] and [x["path"] for x in recs] == ["/v1/complete"],
          f"paths 4: [auth] paths in config.toml replaces the list: only /v1/complete passes now (a trailing slash on the entry is ignored): {[c['code'] for c in codes]}")
    PY = mkhome("proxy-badpaths", auth_extra='paths = "/v1/messages"\n')
    rc_b, out_b, err_b = tool_cli(["--home", PY, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY))
    check(rc_b == 1 and err_b.strip() == "refused: config.toml: [auth] paths must be a list of paths that start with /", f"paths 5: a paths that is not a list is refused: {err_b.strip()!r}")
    rc_p, out_p, _ = tool_cli(["--home", PX, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY)); rc_d, out_d, _ = tool_cli(["--home", PF, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY))
    check("paths: /v1/complete/ ([auth] paths); any other path gets 403" in out_p and "paths: /v1/messages, /v1/messages/count_tokens ([auth] paths); any other path gets 403 and is not forwarded, and the real key is never attached to it" in out_d
          and "processes: every process the run starts is killed with it, by ancestry and by the run's marker; nothing outlives the ledger line" in out_d and out_d.index("time: killed after") < out_d.index("processes: every process"),
          "paths 6: the dry run names the list and, under the time line, says what happens to the run's processes")

    # ---- the CLI sends the key as a bearer token
    rc, out, err, r, s, recs = fresh(PF, "MODE:bearer")
    check(rc == 0 and len(recs) == 1 and recs[0]["headers"].get("authorization") == f"Bearer {TESTKEY}" and "x-api-key" not in recs[0]["headers"], f"proxy: a token sent as a bearer is accepted and the real key goes out as a bearer: {recs and recs[0]['headers'].get('authorization')}")
    # ---- --require-api-key: the token's variable is the one key source
    rc, out, err, r, s, recs = fresh(PF, "MODE:helpersource")
    check(rc == 1 and s["status"] == "killed: key source is 'apiKeyHelper', not one of ANTHROPIC_API_KEY, so the run would not bill an API key" and not recs,
          f"proxy: --require-api-key through the proxy accepts the token's variable only: {s['status']}")

    # ---- every way out closes the door: SIGTERM, and an exception after launch
    timer = threading.Timer(2.0, lambda: os.kill(os.getpid(), signal.SIGTERM)); timer.start()
    rc, out, err, r, s, recs = fresh(PF, "MODE:sleep", ["--timeout", "20"])
    timer.cancel()
    def closed(run_folder):
        url = json.load(open(os.path.join(run_folder, "cli-env.json")))["ANTHROPIC_BASE_URL"]
        try: socket.create_connection(("127.0.0.1", int(url.rsplit(":", 1)[1])), timeout=2).close(); return None
        except OSError as x: return type(x).__name__
    check(rc == 1 and s["status"] == "killed: interrupted" and s["true_cost"] == round(SONNET, 4) and not s["true_cost_is_ceiling"] and closed(r) == "ConnectionRefusedError",
          f"proxy 14: SIGTERM ends the run, books the proxy's total (not a ceiling), and closes the door: {s['status']}, {closed(r)}")
    real_rb = siwithin.receipt_bytes
    def boom(*a, **k): raise RuntimeError("boom")
    siwithin.receipt_bytes = boom; raised = None
    try: UP.recs.clear(); whole(["--home", PF, "--dir", ED], brief="MODE:basic", extra_env=KEY)
    except RuntimeError as x: raised = str(x)
    finally: siwithin.receipt_bytes = real_rb
    check(raised == "boom" and closed(last_run(PF)[0]) == "ConnectionRefusedError", f"proxy 14b: an exception after launch closes the door too ({raised}, {closed(last_run(PF)[0])})")

    # ---- the proxy by itself: keep-alive, the 502, the seal, the wall's one call to stop, and the close
    import http.client
    prices = siwithin.DEFAULT_CONFIG["prices"]; reqbody = json.dumps({"model": "claude-sonnet-5-5", "stream": False}).encode()
    def unit(name, upstream=UPSTREAM, budget=5.0, timeout=30):
        px = siwithin.KeyProxy(TESTKEY, "x-api-key", upstream, timeout, prices, budget, os.path.join(TMP, name + ".jsonl")); px.start(); return px
    def post(c, token, path="/v1/messages"):
        c.request("POST", path, reqbody, {"x-api-key": token, "content-type": "application/json"}); r = c.getresponse(); return r.status, r.getheader("Transfer-Encoding"), r.read()
    px = unit("unit-a"); c = http.client.HTTPConnection("127.0.0.1", px.port, timeout=10); UP.recs.clear()
    a1, a2 = post(c, px.token), post(c, px.token, "/v1/messages?beta=true")
    lines = jl(os.path.join(TMP, "unit-a.jsonl"))
    check(a1[0] == a2[0] == 200 and a1[1] == "chunked" and json.loads(a1[2])["usage"]["output_tokens"] == 20 and UP.recs[-1]["path"] == "/v1/messages?beta=true" and len({x["client"] for x in lines}) == 1 and len(lines) == 2,
          "proxy 15: keep-alive on the client side: two requests on one connection, the query forwarded, the body chunked")
    px.seal(); a3 = post(http.client.HTTPConnection("127.0.0.1", px.port, timeout=10), px.token); lines = jl(os.path.join(TMP, "unit-a.jsonl"))
    check(a3[0] == 402 and json.loads(a3[2])["error"]["message"] == "SIwithin: the run has ended" and lines[-1]["refused"] == "ended" and len(UP.recs) == 2, "proxy 15b: once sealed every request gets 402 and nothing is forwarded")
    px2 = unit("unit-b"); c5 = http.client.HTTPConnection("127.0.0.1", px2.port, timeout=10); post(c5, px2.token); px2.close()
    try: post(c5, px2.token); cut = None
    except (OSError, http.client.HTTPException) as x: cut = type(x).__name__
    try: socket.create_connection(("127.0.0.1", px2.port), timeout=2).close(); refused = None
    except OSError as x: refused = type(x).__name__
    px.close()
    check(cut is not None and refused == "ConnectionRefusedError", f"proxy 15c: close() cuts a connection the run held open ({cut}) and nothing can connect after ({refused})")
    px3 = unit("unit-c", upstream="http://127.0.0.1:1"); b = post(http.client.HTTPConnection("127.0.0.1", px3.port, timeout=10), px3.token); px3.close()
    check(b[0] == 502 and json.loads(b[2])["error"] == {"type": "api_error", "message": "SIwithin: the upstream did not answer (ConnectionRefusedError)"} and jl(os.path.join(TMP, "unit-c.jsonl"))[0]["status"] == 502,
          "proxy 15d: an upstream that cannot be reached: 502 in the error shape, logged")
    stops = []; px4 = unit("unit-d", budget=0.0003); px4.on_wall = stops.append; c6 = http.client.HTTPConnection("127.0.0.1", px4.port, timeout=10)
    w = [post(c6, px4.token)[0], post(c6, px4.token), post(c6, px4.token)]; px4.close()
    check(w[0] == 200 and w[1][0] == 402 and w[2][0] == 402 and json.loads(w[1][2])["error"] == {"type": "billing_error", "message": "SIwithin: budget $0.0003 reached at $0.0004 true"}
          and stops == ["killed: budget $0.0003 reached at $0.0004 true"], f"proxy 15e: the wall: 402 after the budget, and the stop is called once, on the first refusal: {stops}")

    # ---- the plan: the dry run, a helper in settings.json, no key, a key command, auth = env
    made = []
    real_kp = siwithin.KeyProxy; siwithin.KeyProxy = lambda *a, **k: made.append(a) or real_kp(*a, **k)
    n_runs = len(os.listdir(os.path.join(PF, "runs")))
    try: rc, out, err = whole(["--home", PF, "--dir", ED, "--dry-run"], extra_env=KEY)
    finally: siwithin.KeyProxy = real_kp
    rc_s, out_s, err_s = tool_cli(["--home", PF, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY))
    check(rc == 0 and not made and "auth: proxy 127.0.0.1:<port>" in out and not re.search(r"auth: proxy 127\.0\.0\.1:\d", out) and TESTKEY not in out
          and "ok     auth: proxy; the key stays in the runner (from ANTHROPIC_API_KEY); the run sees a token" in out and "ANTHROPIC_BASE_URL" in out and n_runs == len(os.listdir(os.path.join(PF, "runs")))
          and rc_s == 0 and "auth: proxy 127.0.0.1:<port>" in out_s and TESTKEY not in out_s,
          f"proxy 10: --dry-run prints the auth line and starts no server: no proxy was built, no port in the text, no run folder ({rc}, {err!r})")
    rc_n, out_n, _ = tool_cli(["--home", PF, "--dir", PROJ, "--dry-run"])
    check(rc_n == 0 and "warn   auth: no key: export ANTHROPIC_API_KEY for the runner, or set [auth] key_command" in out_n, "proxy 10b: a dry run with no key warns and goes on")

    settings = os.path.join(PF, "claude-config", "settings.json")
    write(settings, json.dumps({"apiKeyHelper": "/made/up/helper.sh"}))
    n_lines = len(ledger(PF)); n_runs = len(os.listdir(os.path.join(PF, "runs")))
    rc, out, err = whole(["--home", PF, "--dir", ED], extra_env=KEY)
    check(rc == 1 and f"refused: auth: a key helper in {settings} is readable by the run; move it to [auth] key_command in config.toml and remove it from settings.json" in err
          and len(ledger(PF)) == n_lines and len(os.listdir(os.path.join(PF, "runs"))) == n_runs,
          f"proxy 11: a settings.json that names apiKeyHelper in the run's config directory is refused before launch: {err.strip()[:120]}")
    write(settings, json.dumps({"theme": "dark"}))
    rc, out, err = tool_cli(["--home", PF, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY))
    check(rc == 0 and "refuse auth: a key helper" not in out, "proxy 11b: a settings.json without a helper does not refuse")
    os.remove(settings)

    n_lines = len(ledger(PF)); n_runs = len(os.listdir(os.path.join(PF, "runs")))
    rc, out, err = whole(["--home", PF, "--dir", ED], extra_env={"ANTHROPIC_API_KEY": None})
    check(rc == 1 and "refused: auth: no key: export ANTHROPIC_API_KEY for the runner, or set [auth] key_command" in err and len(ledger(PF)) == n_lines and len(os.listdir(os.path.join(PF, "runs"))) == n_runs,
          f"proxy 12: no key in the runner's environment and no key_command: refused before launch: {err.strip()[:120]}")
    PK = mkhome("proxy-cmd", auth_extra=f"key_command = 'echo {TESTKEY}'\n")
    rc, out, err, r, s, recs = fresh(PK, "MODE:basic", env={"ANTHROPIC_API_KEY": None})
    files = [os.path.join(dp, f) for dp, _, fs in os.walk(r) for f in fs]
    check(rc == 0 and s["status"] == "done" and len(recs) == 3 and all(x["headers"].get("x-api-key") == TESTKEY for x in recs) and not [f for f in files if TESTKEY.encode() in open(f, "rb").read()]
          and TESTKEY not in out + err, f"proxy 12b: with [auth] key_command the run goes ahead and the upstream sees the key it printed ({rc}, {err!r})")
    PB = mkhome("proxy-badcmd", auth_extra="key_command = 'exit 3'\n")
    rc, out, err = whole(["--home", PB, "--dir", ED], extra_env={"ANTHROPIC_API_KEY": None})
    check(rc == 1 and "refused: auth: [auth] key_command exited 3" in err, f"proxy 12c: a key_command that fails refuses the run, naming no key: {err.strip()[:100]}")

    PE = mkhome("proxy-env", adapter='bin = "pclaude"\nauth = "env"\n', auth_extra='[fence]\nnetwork = "open"\n')
    rc_p, out_p, _ = tool_cli(["--home", PE, "--dir", PROJ, "--dry-run", "--network", "proxy"], env=dict(ENV, **KEY))
    check(rc_p == 1 and 'refuse network: proxy ([fence] network) allows the run only the key proxy\'s port, and adapter claude has auth = "env", which starts no proxy' in out_p,
          "proxy 13b: the same home under network = proxy is refused in the checks: an env adapter has no proxy port to allow")
    rc, out, err, r, s, recs = fresh(PE, "MODE:envdump", env=KEY)
    cli_env = json.load(open(os.path.join(r, "cli-env.json")))
    rc_e, out_e, _ = tool_cli(["--home", PE, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY))
    check(rc == 0 and cli_env.get("ANTHROPIC_API_KEY") == TESTKEY and "ANTHROPIC_BASE_URL" not in cli_env and not os.path.exists(os.path.join(r, "proxy.jsonl")) and not recs
          and "auth: proxy" not in open(os.path.join(r, "command.txt")).read() and s["proxy_cost"] is None and "proxy_requests" in s and len(json.load(open(os.path.join(r, "receipt.json")))["files"]) == 7
          and rc_e == 0 and "warn   auth: env; the key is in the run's environment and every command the run starts can read it" in out_e and "auth: proxy 127" not in out_e,
          f"proxy 13: auth = \"env\" in the config: 0.2.1's environment, the warn line, no proxy, no proxy.jsonl")
    PU = mkhome("proxy-upstream"); write(os.path.join(PU, "config.toml"), '[adapters.claude]\nbin = "pclaude"\n[auth]\nupstream = "http://example.com"\n')
    rc_h, out_h, _ = tool_cli(["--home", PU, "--dir", PROJ, "--dry-run"], env=dict(ENV, **KEY))
    check(rc_h == 1 and "refuse auth: upstream 'http://example.com' must be an https:// address" in out_h, "proxy: an upstream that is http and not loopback is refused, the key would travel in clear")
    rc, out, err, r, s, recs = fresh(PF, "MODE:basic", env=KEY)
    check(rc == 0 and s["status"] == "done" and siwithin.ledger_total(os.path.join(PF, "ledger.md"))[1] == len(ledger(PF)) - 1, "proxy: a run after the refusals is booked as before, every line counted")
    print(f"   (key proxy checks took {time.time() - t0:.1f}s)")


def walk_tests(whole, last_run, EH, ED, BIN):
    import fcntl, glob, signal, threading

    def alive(pid):
        try: os.kill(pid, 0); return True
        except ProcessLookupError: return False
        except PermissionError: return True

    def dead_soon(pid, wait=2.0):  # a killed process is reaped by launchd a moment later
        end = time.time() + wait
        while alive(pid) and time.time() < end: time.sleep(0.05)
        return not alive(pid)

    write(os.path.join(BIN, "wclaude"), f"#!{sys.executable}\n" + WCLAUDE); os.chmod(os.path.join(BIN, "wclaude"), 0o755)
    WH = os.path.join(EH, ".config", "siwithin-walk"); os.makedirs(WH)
    write(os.path.join(WH, "cap"), "100")
    write(os.path.join(WH, "config.toml"), '[adapters.claude]\nbin = "wclaude"\nauth = "env"\n[fence]\nnetwork = "open"\n')
    NOTE = "processes outlived the CLI and were killed"
    group("the walls: the kill walk")
    show[0] = True
    pids = []
    try:
        # ---- 1: a process in a session of its own, and a budget stop: it dies with the run, and the lock is not freed before it has stopped
        seen = {}

        def monitor():  # the lock is tried from a second open file, as another launch would try it; it is free only when the runner has returned
            end = time.time() + 90
            while time.time() < end and "free" not in seen:
                hbs = glob.glob(os.path.join(WH, "runs", "*", "hb.txt"))
                if hbs:
                    f = open(os.path.join(WH, "lock"), "a+")
                    try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB); seen["free"], seen["hb"] = time.time(), hbs[0]
                    except OSError: pass
                    finally: f.close()
                time.sleep(0.02)
        th = threading.Thread(target=monitor, daemon=True); th.start()
        rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet", "--budget", "0.5", "--timeout", "40"], brief="MODE:budget")
        back = time.time(); th.join(5)
        r, s = last_run(WH); hb = os.path.join(r, "hb.txt")
        lines = open(hb).read().split("\n"); pid = int(lines[0].split()[1]); pids.append(pid)
        sizes, calm = [], None
        while time.time() - back < 3:  # no growth over two looks 0.4 s apart: it has stopped
            sizes.append(os.path.getsize(hb)); time.sleep(0.4)
            if len(sizes) >= 2 and sizes[-1] == sizes[-2]: calm = time.time() - back; break
        check(rc == 1 and s["status"] == "killed: budget $0.50 reached at $0.5502 true" and calm is not None and calm < 3 and dead_soon(pid),
              f"walk 1: the budget stop kills a detached process: the heartbeat stopped within {calm if calm is None else round(calm, 1)}s of the runner's return, the process is gone ({s['status']})")
        times = [float(x) for x in open(hb).read().split("\n")[1:] if x]
        check(s["outlived"] == 1 and any(n == f"1 {NOTE}" for n in s["notes"]) and f"1 {NOTE}" in out,
              f"walk 1b: summary.json says outlived is 1, and the note is there and is printed: {s['outlived']}, {s['notes']}")
        check("free" in seen and seen["hb"] == hb and times and max(times) <= seen["free"] and len(times) >= 2,
              f"walk 1c: the lock was free only after the heartbeat stopped: the last of {len(times)} beats is {round(seen['free'] - max(times), 3) if 'free' in seen and times else '-'}s before the lock was seen free ({seen.get('hb') == hb})")

        # ---- 2: the CLI exits on its own and leaves a detached process behind
        t0 = time.time(); rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet", "--timeout", "40"], brief="MODE:exit"); took = time.time() - t0
        r, s = last_run(WH); pid = int(open(os.path.join(r, "hb.txt")).read().split("\n")[0].split()[1]); pids.append(pid)
        check(rc == 0 and s["status"] == "done" and took < 5 and dead_soon(pid) and s["outlived"] == 1 and any(n == f"1 {NOTE}" for n in s["notes"]),
              f"walk 2: a clean exit that leaves a detached process: the runner returned in {took:.1f}s, the process is dead, outlived {s['outlived']} ({s['status']})")

        # ---- 2b: the program's launcher exits at once, so by the first look the program is in no one's ancestry; the timer stops the CLI, as the live outlive brief ended (14 October 2026)
        t0 = time.time(); rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet", "--timeout", "4"], brief="MODE:orphan"); took = time.time() - t0
        r, s = last_run(WH); pid = int(open(os.path.join(r, "hb.txt")).read().split("\n")[0].split()[1]); pids.append(pid)
        check(s["status"] == "killed: timeout 4s" and took < 12 and dead_soon(pid) and s["outlived"] == 1 and any(n == f"1 {NOTE}" for n in s["notes"]),
              f"walk 2b: a program whose launcher has exited is found by the marker at the stop's first look, killed and counted: returned in {took:.1f}s, outlived {s['outlived']} ({s['status']})")

        # ---- 3: a detached process that holds the CLI's stdout pipe: the read loop does not wait on it
        t0 = time.time(); rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet", "--timeout", "40"], brief="MODE:pipe"); took = time.time() - t0
        r, s = last_run(WH); pid = int(open(os.path.join(r, "hold.txt")).read().split("\n")[0].split()[1]); pids.append(pid)
        check(rc == 0 and s["status"] == "done" and took < 5 and dead_soon(pid) and s["outlived"] == 1,
              f"walk 3: a detached process holding the pipe is found by the run's marker and killed, which closes the pipe: returned in {took:.1f}s, outlived {s['outlived']}")
        t0 = time.time(); rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet", "--timeout", "40"], brief="MODE:scrub"); took = time.time() - t0
        r, s = last_run(WH); pid = int(open(os.path.join(r, "hold.txt")).read().split("\n")[0].split()[1]); pids.append(pid)
        check(rc == 0 and s["status"] == "done" and 2.5 < took < 5 and alive(pid) and s["outlived"] == 0 and open(os.path.join(r, "result.md")).read() == "walk run done",
              f"walk 3b: an orphan with a scrubbed environment is beyond the walk and holds the pipe: the loop still ended {took:.1f}s after the CLI, with its result read; the orphan is alive: {alive(pid)}")
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass

        # ---- no ps: a note, the run goes on
        real_ps = siwithin.PS; siwithin.PS = os.path.join(BIN, "no-such-ps")
        try: rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet"], brief="MODE:plain")
        finally: siwithin.PS = real_ps
        r, s = last_run(WH)
        check(rc == 0 and s["status"] == "done" and s["outlived"] == 0 and sum("could not be read" in n for n in s["notes"]) == 1,
              f"walk 4: ps missing: the run completes, with one note: {s['notes']}")
        rc, out, err = whole(["--home", WH, "--dir", ED, "--model", "sonnet"], brief="MODE:plain")
        r, s = last_run(WH)
        check(rc == 0 and s["outlived"] == 0 and not s["notes"], f"walk 5: a clean run: outlived 0 and no note ({s['notes']})")
        claude, codex = siwithin.DEFAULT_CONFIG["adapters"]["claude"], siwithin.DEFAULT_CONFIG["adapters"]["codex"]
        check(siwithin.run_markers({"CLAUDE_CODE_TMPDIR": "/r/tmp", "CLAUDE_CONFIG_DIR": "/c", "ANTHROPIC_BASE_URL": "http://127.0.0.1:1"}, claude) == ["CLAUDE_CODE_TMPDIR=/r/tmp"]
              and siwithin.run_markers({"CODEX_HOME": "/c/codex"}, codex) == ["CODEX_HOME=/c/codex"]
              and siwithin.run_markers({"CODEX_HOME": "/c", "X_URL": "http://h"}, dict(codex, base_url_env="X_URL")) == ["CODEX_HOME=/c", "X_URL=http://h"],
              "walk 6: the run's marker is its temp root, or for an adapter without one its config directory and API address")
    finally:
        show[0] = False
        for pid in pids:
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass


def reconcile_tests():
    import datetime, http.server, threading, urllib.parse
    UTC = datetime.timezone.utc
    MARK = "sk-ant-admin01-LEAKMARKER0123456789abcdef"  # made up: the admin key of every test below, which must reach the fake server's header and nowhere else
    KEYID = "apikey_01AbCdEfGhIjKl"
    group("reconcile")

    class Fake(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            u, S = urllib.parse.urlsplit(self.path), self.server
            q = urllib.parse.parse_qs(u.query)
            S.seen.append({"path": u.path, "query": q, "headers": {k.lower(): v for k, v in self.headers.items()}})
            if S.fail: status, body = S.fail
            elif self.headers.get("x-api-key") != MARK: status, body = 401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}
            elif u.path.endswith("/api_keys"): status, body = 200, S.keys
            else: status, body = 200, S.pages.get((q.get("page") or [None])[0], {"data": [], "has_more": False, "next_page": None})
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    class Srv(http.server.ThreadingHTTPServer): daemon_threads = True

    try: FAKE = Srv(("127.0.0.1", 0), Fake)
    except OSError as x:
        print(f"SKIPPED reconcile checks: no loopback server can be bound here ({x}); the tests are written, run them where one can")
        return
    FAKE.seen, FAKE.pages, FAKE.keys, FAKE.fail = [], {}, {"data": [], "has_more": False}, None
    threading.Thread(target=FAKE.serve_forever, daemon=True).start()
    base = os.path.join(TMP, "reconcile"); os.makedirs(base)
    script = os.path.join(base, "admin-key.sh"); write(script, f"#!/bin/sh\nprintf '%s\\n' {MARK}\n"); os.chmod(script, 0o755)  # outside every home: a config that named the marker would hold it
    homes, outputs = [], []
    z = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    local = lambda t: t.astimezone().replace(tzinfo=None)  # the ledger's and proxy.jsonl's times are the machine's local time
    HOUR = datetime.timedelta(hours=1)
    B0 = datetime.datetime(2026, 10, 16, 12, 0, tzinfo=UTC); B1 = B0 + HOUR
    SINCE, UNTIL = local(B0 - 3 * HOUR).strftime("%Y-%m-%dT%H:%M"), local(B1 + 3 * HOUR).strftime("%Y-%m-%dT%H:%M")
    SUMMARY = re.compile(r"reconcile: \d{4}-\d\d-\d\d \d\d:\d\d to \d{4}-\d\d-\d\d \d\d:\d\d \| provider \$\d+\.\d{4} \| runs \$\d+\.\d{4} \| unaccounted \$\d+\.\d{4} in \d+ buckets \| over \$\d+\.\d{4} in \d+ \| unpriced \d+ \| key apikey_01Ab…")

    def res(model="claude-sonnet-5-5", tier="standard", unc=0, read=0, w5=0, w1=0, out=0, web=0):
        return {"api_key_id": KEYID, "model": model, "service_tier": tier, "uncached_input_tokens": unc, "cache_read_input_tokens": read,
                "cache_creation": {"ephemeral_5m_input_tokens": w5, "ephemeral_1h_input_tokens": w1}, "output_tokens": out, "server_tool_use": {"web_search_requests": web}}

    def bucket(t, *results): return {"starting_at": z(t), "ending_at": z(t + HOUR), "results": list(results)}
    def page(*buckets, more=None): return {"data": list(buckets), "has_more": more is not None, "next_page": more}
    FULL = dict(unc=1_000_000, read=2_000_000, w5=500_000, w1=400_000, out=100_000, web=3)  # priced by hand: 2.00 + 0.20 + 1.25 + 0.4 x 2.5 x 1.6 = 1.60 + 1.00 + 0.03 = 6.08

    def config(ids='["' + KEYID + '"]', cmd=script):
        return (f'[auth]\nupstream = "http://127.0.0.1:{FAKE.server_address[1]}"\n[prices]\ncache_write_1h_factor = 1.6\nweb_search = 0.01\n"claude-sonnet-5-5" = [2.0, 2.5, 0.10, 10.0]\n'
                f'[reconcile]\nadmin_key_command = "{cmd}"\napi_key_ids = {ids}\ntolerance = 0.05\n')

    def mk_home(name, runs=(), **cfg):
        """runs: (start in UTC, minutes, true dollars, [(UTC time, cost)], or None for a run with no proxy log)."""
        h = os.path.join(base, name); os.makedirs(os.path.join(h, "runs")); homes.append(h)
        write(os.path.join(h, "config.toml"), config(**cfg))
        lines = ["# siwithin ledger: one line per run"]
        for i, (t0, mins, true, reqs) in enumerate(runs):
            lines.append(f"{local(t0):%Y-%m-%d %H:%M} | job | /x | claude sonnet - | 3 turns | {mins:.1f} min | cli $0.0000 | true ${true:.4f} | in 0k out 0k | runs/r{i} | done")
            if reqs is not None:
                ok = [json.dumps({"t": local(t).isoformat(timespec="milliseconds"), "path": "/v1/messages", "model": "claude-sonnet-5-5", "status": 200, "usage": {}, "cost": c, "total": 0, "client": 1, "refused": None}) for t, c in reqs]
                refused = json.dumps({"t": local(t0).isoformat(timespec="milliseconds"), "path": "/v1/messages", "model": None, "status": 402, "usage": None, "cost": None, "total": 0, "client": 1, "refused": "budget"})
                write(os.path.join(h, "runs", f"r{i}", "proxy.jsonl"), "\n".join(ok + [refused]) + "\n")
        write(os.path.join(h, "ledger.md"), "\n".join(lines) + "\n")
        return h

    def rec(home, *extra, since=SINCE, until=UNTIL):
        rc, out, err = tool_cli(["--home", home, "--reconcile", since, *(["--until", until] if until else []), *extra])
        outputs.append(out + err)
        return rc, out, err

    def newest(home, ext):
        d = os.path.join(home, "reconcile"); return os.path.join(d, max((f for f in os.listdir(d) if f.endswith(ext)), key=lambda f: (os.stat(os.path.join(d, f)).st_mtime_ns, f)))

    def last_json(home): return json.load(open(newest(home, ".json")))
    def summary(out): return out.rstrip("\n").split("\n")[-1]

    def inproc(args):
        saved = sys.stdout, sys.stderr
        o, e = io.StringIO(), io.StringIO(); sys.stdout, sys.stderr = o, e
        try: rc = siwithin.main(args)
        finally: sys.stdout, sys.stderr = saved
        outputs.append(o.getvalue() + e.getvalue())
        return rc, o.getvalue(), e.getvalue()

    def run_at(t0, cost, mins=25.0, n=2):  # a run whose proxy.jsonl holds n requests of cost / n each, in the bucket t0 is in
        return (t0 + datetime.timedelta(minutes=10), mins, cost, [(t0 + datetime.timedelta(minutes=15 + i), round(cost / n, 4)) for i in range(n)])

    # 1: paging
    h1 = mk_home("paging")
    FAKE.pages = {None: page(bucket(B0, res(unc=1_000_000)), more="page_2"), "page_2": page(bucket(B1, res(out=100_000)))}  # $2.00 and $1.00
    FAKE.seen.clear(); rc, out, err = rec(h1)
    q0 = FAKE.seen[0]["query"]
    check(len(FAKE.seen) == 2 and FAKE.seen[1]["query"].get("page") == ["page_2"] and "page" not in q0 and "provider $3.0000 |" in summary(out) and last_json(h1)["totals"]["provider"] == 3.0,
          f"reconcile 1: two pages joined by has_more and next_page, the figures the sum of both: {len(FAKE.seen)} requests, {summary(out)!r}")
    check(FAKE.seen[0]["path"] == "/v1/organizations/usage_report/messages" and q0["api_key_ids[]"] == [KEYID] and q0["group_by[]"] == ["api_key_id", "model", "service_tier"] and q0["bucket_width"] == ["1h"]
          and q0["limit"] == ["168"] and q0["starting_at"][0].endswith("Z") and FAKE.seen[0]["headers"]["x-api-key"] == MARK and FAKE.seen[0]["headers"]["anthropic-version"] == "2023-06-01",
          f"reconcile 1b: the request carries the key ids, the three groupings, the width and the page size, the admin key and the version: {q0}")

    # 2: arithmetic
    h2 = mk_home("arithmetic")
    FAKE.pages = {None: page(bucket(B0, res(**FULL)))}
    rc, out, err = rec(h2); j2 = last_json(h2)
    check(j2["totals"]["provider"] == 6.08 and j2["buckets"][0]["provider"] == 6.08 and "provider $6.0800 |" in summary(out) and "| 6.0800 |" in open(newest(h2, ".md")).read(),
          f"reconcile 2: one bucket of every kind of token prices to the $6.08 worked by hand, the 1h factor applied: {j2['totals']['provider']}")

    # 3: unaccounted
    h3 = mk_home("unaccounted")
    rc, out, err = rec(h3)
    check(rc == 1 and SUMMARY.fullmatch(summary(out)) and "unaccounted $6.0800 in 1 buckets" in summary(out) and f"unaccounted: {z(B0)} provider $6.0800, runs $0.0000" in out and "report: " in out
          and out.index("report: ") < out.index(summary(out)), f"reconcile 3: provider spend with no run is unaccounted, exit 1, the summary line names it: rc {rc}, {summary(out)!r}")

    # 4: ok
    h4 = mk_home("ok", [run_at(B0, 6.08)])
    rc, out, err = rec(h4)
    check(rc == 0 and SUMMARY.fullmatch(summary(out)) and "provider $6.0800 | runs $6.0800 | unaccounted $0.0000 in 0 buckets | over $0.0000 in 0 |" in summary(out) and last_json(h4)["buckets"][0]["verdict"] == "ok",
          f"reconcile 4: the same bucket with a run whose proxy.jsonl matches is ok, exit 0: rc {rc}, {summary(out)!r}")

    # 5: over, and within the tolerance
    rc, out, err = rec(mk_home("over", [run_at(B0, 5.58)])); h5b = mk_home("within", [run_at(B0, 6.04)])
    rcb, outb, errb = rec(h5b)
    check(rc == 1 and "over $0.5000 in 1 |" in summary(out) and "unaccounted $0.0000 in 0 buckets" in summary(out) and rcb == 0 and "over $0.0000 in 0 |" in summary(outb) and last_json(h5b)["buckets"][0]["difference"] == 0.04,
          f"reconcile 5: a run $0.50 short of the provider is over, exit 1; $0.04 short is within the $0.05 tolerance, exit 0: {summary(out)!r} {summary(outb)!r}")

    # 8: unpriced, with a run active and with none
    h8 = mk_home("unpriced", [run_at(B0, 0.0)]); h8b = mk_home("unpriced-none")
    FAKE.pages = {None: page(bucket(B0, res(model="claude-mystery-9", unc=100, out=50)))}
    rc, out, err = rec(h8); rcb, outb, errb = rec(h8b); r8 = last_json(h8)["buckets"][0]
    check(rc == 0 and "provider $0.0000 |" in summary(out) and "unpriced 1 |" in summary(out) and r8["unpriced"] and r8["results"][0]["dollars"] is None and (r8["results"][0]["unc"], r8["results"][0]["out"]) == (100, 50)
          and "unpriced: claude-mystery-9" in out and "| 100 | 0 | 0 | 0 | 50 | 0 | unpriced |" in open(newest(h8, ".md")).read(),
          f"reconcile 8: a model with no price is shown with its tokens, not priced, and counted: {summary(out)!r}")
    check(rcb == 1 and "unaccounted $0.0000 in 1 buckets" in summary(outb) and "unpriced 1 |" in summary(outb), f"reconcile 8b: tokens of a model with no price, with no run active, are still unaccounted: {summary(outb)!r}")
    FAKE.pages = {None: page(bucket(B0, res(tier="priority", unc=1_000_000)))}
    h8c = mk_home("tier"); rc, out, err = rec(h8c)
    check("finding: service tier priority in 1 buckets" in out and last_json(h8c)["buckets"][0]["provider"] == 2.0, f"reconcile 8c: a service tier other than standard is priced as standard and named: {out.strip()[:200]!r}")

    # 9: the CSV way
    FAKE.pages = {None: page(bucket(B0, res(**FULL)))}
    head = "Date (UTC),Model,Uncached Input Tokens,Cache Read Input Tokens,Cache Creation 5m Input Tokens,Cache Creation 1h Input Tokens,Output Tokens,Web Search Requests"
    csv_ok, csv_bad = os.path.join(base, "usage.csv"), os.path.join(base, "usage-bad.csv")
    write(csv_ok, head + "\n2026-10-16 12:00,claude-sonnet-5-5,1000000,2000000,500000,400000,100000,3\n2026-10-16 13:00,claude-sonnet-5-5,0,0,0,0,0,0\n")
    write(csv_bad, head.replace(",Output Tokens", "") + "\n2026-10-16 12:00,claude-sonnet-5-5,1,2,3,4,3\n")
    seen = len(FAKE.seen); rc, out, err = rec(h4, "--csv", csv_ok); jc = last_json(h4)
    check(rc == 0 and len(FAKE.seen) == seen and jc["totals"]["provider"] == j2["totals"]["provider"] and jc["buckets"][0]["provider"] == j2["buckets"][0]["provider"] == 6.08 and jc["bucket"] == "1h"
          and "key -" in summary(out), f"reconcile 9: a CSV export reconciles to the same figures as the API's JSON, with no request made: rc {rc}, {summary(out)!r} {err!r}")
    rc, out, err = rec(h4, "--csv", csv_bad)
    check(rc == 2 and err.strip().count("\n") == 0 and f"the header row is: {head.replace(',Output Tokens', '')}" in err and "output" in err.split("the header row")[0] and not out,
          f"reconcile 9b: a header with a column missing is refused with the header printed: {err.strip()[:200]!r}")

    # 7: refusals
    FAKE.pages = {}; seen = len(FAKE.seen)
    rc, out, err = rec(mk_home("no-command", cmd=""))
    check(rc == 2 and "admin_key_command" in err and "--csv" in err and err.strip().count("\n") == 0 and len(FAKE.seen) == seen, f"reconcile 7: no admin_key_command and no --csv refuses naming both ways in: {err.strip()!r}")
    FAKE.keys = {"data": [{"id": "apikey_01AAA", "name": "runs key", "partial_key_hint": "sk-ant-api03-R2D...igAA", "status": "active", "created_at": "2024-10-30T23:58:27Z"},
                          {"id": "apikey_01BBB", "name": "other", "partial_key_hint": "sk-ant-api03-Q9X...zzBB", "status": "active"}], "has_more": False, "first_id": "apikey_01AAA", "last_id": "apikey_01BBB"}
    FAKE.seen.clear(); rc, out, err = rec(mk_home("no-ids", ids="[]"))
    check(rc == 2 and out.strip().split("\n") == ["apikey_01AAA | runs key | sk-ant-api03-R2D...igAA", "apikey_01BBB | other | sk-ant-api03-Q9X...zzBB"] and 'api_key_ids = ["<one of the ids above>"]' in err
          and [s["path"] for s in FAKE.seen] == ["/v1/organizations/api_keys"], f"reconcile 7b: an empty api_key_ids lists the keys (id, name, hint) and refuses with the config line: {out.strip()!r} {err.strip()!r}")

    # 6: the admin key never leaves
    FAKE.fail = (401, {"type": "error", "error": {"type": "authentication_error", "message": f"invalid x-api-key {MARK} and sk-ant-api03-OTHERKEY12345"}})
    rc, out, err = rec(h4)
    check(rc == 2 and "401" in err and "authentication_error" in err and "<key>" in err and MARK not in err and "sk-ant-api03" not in err and err.strip().count("\n") == 0,
          f"reconcile 6: a 401 is reported with its status and error type, the key and any sk-ant string replaced by <key>: {err.strip()!r}")
    FAKE.fail = (500, "not json"); rc, out, err = rec(h4)
    check(rc == 2 and "500" in err and err.strip().count("\n") == 0, f"reconcile 6b: a status other than 200 whose body is not JSON is still reported: {err.strip()!r}")
    FAKE.fail = None; seen, reports = len(FAKE.seen), len(os.listdir(os.path.join(h4, "reconcile"))); rc, out, err = rec(h4, "--dry-run")
    check(rc == 0 and len(FAKE.seen) == seen and len(os.listdir(os.path.join(h4, "reconcile"))) == reports and "x-api-key: <key>" in out and "usage_report/messages?starting_at=" in out and "api_key_ids[]=" + KEYID in out,
          f"reconcile 6c: a dry run prints the URL and the headers with the key as <key>, requests nothing and writes nothing: {out.strip()[:160]!r}")
    files = [os.path.join(d, f) for h in homes for d, _, fs in os.walk(h) for f in fs]
    check(not [f for f in files if MARK.encode() in open(f, "rb").read()] and not [o for o in outputs if MARK in o] and len(files) > 20,
          f"reconcile 6d: the admin key is in no file under any home, no report, no output and no error text: {len(files)} files, {len(outputs)} outputs read")

    # 10: nothing is run, nothing is booked
    FAKE.pages = {None: page(bucket(B0, res(**FULL)))}
    shim = os.path.join(base, "sandbox-shim"); flag = os.path.join(base, "sandbox-was-run"); write(shim, f"#!/bin/sh\necho run >> {flag}\n"); os.chmod(shim, 0o755)
    before, runs_before, saved = open(os.path.join(h4, "ledger.md")).read().split("\n"), sorted(os.listdir(os.path.join(h4, "runs"))), siwithin.SANDBOX_EXEC
    siwithin.SANDBOX_EXEC = shim
    try: rc, out, err = inproc(["--home", h4, "--reconcile", SINCE, "--until", UNTIL])
    finally: siwithin.SANDBOX_EXEC = saved
    check(rc == 0 and "provider $6.0800 |" in summary(out) and not os.path.exists(flag) and open(os.path.join(h4, "ledger.md")).read().split("\n") == before and sorted(os.listdir(os.path.join(h4, "runs"))) == runs_before
          and not os.path.exists(os.path.join(h4, "lock")), f"reconcile 10: --reconcile starts no sandbox-exec and adds no ledger line ({len(before)} lines before and after): rc {rc}, {err!r}")

    # 11: the red scorer's fake pass is unchanged
    rr = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "red", "run.py"), "--fake"], capture_output=True, text=True, timeout=120)
    check(rr.returncode == 0 and "92 of 92 checks passed" in rr.stdout and rr.stdout.strip().endswith("PASS"), f"reconcile 11: tests/red/run.py --fake still passes 92 of 92: {rr.stdout.strip().splitlines()[-2:]}")

    # not among the eleven: the watch, the config and the command line
    W0 = datetime.datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - 2 * HOUR; wsince = local(W0 - HOUR).strftime("%Y-%m-%dT%H:%M")
    FAKE.pages = {None: page(bucket(W0, res(unc=1_000_000)))}  # $2.00 in a bucket with no run
    ticks = []; saved_sleep = siwithin.WATCH_SLEEP; siwithin.WATCH_SLEEP = lambda s: ticks.append(s)
    try: rc, out, err = inproc(["--home", mk_home("watch-un"), "--reconcile", wsince, "--every", "60"])
    finally: siwithin.WATCH_SLEEP = saved_sleep
    check(rc == 1 and not ticks and len(out.strip().split("\n")) == 1 and "unaccounted $2.0000 in 1 buckets" in out, f"reconcile watch 1: the first unaccounted above the tolerance ends --every with exit 1, one line: rc {rc}, {out.strip()[:120]!r}")
    hw = mk_home("watch-ok", [run_at(W0, 2.0)])
    FAKE.pages = {None: page(bucket(W0, res(unc=1_000_000)))}; ticks.clear()

    def tick(s):
        ticks.append(s)
        if len(ticks) == 2: FAKE.pages = {None: page(bucket(W0, res(unc=1_010_000)))}  # $2.02: a figure changed, still within the tolerance
        if len(ticks) == 3: raise KeyboardInterrupt
    siwithin.WATCH_SLEEP = tick
    try: rc, out, err = inproc(["--home", hw, "--reconcile", wsince, "--every", "60"])
    finally: siwithin.WATCH_SLEEP = saved_sleep
    lines = [x for x in out.strip().split("\n") if x]
    check(rc == 0 and ticks == [60, 60, 60] and len(lines) == 2 and "provider $2.0000 |" in lines[0] and "provider $2.0200 |" in lines[1], f"reconcile watch 2: --every prints a line only when a figure changed (3 looks, 2 lines): {ticks} {lines}")
    seen = len(FAKE.seen)
    r30, r_until, r_csv = rec(hw, "--every", "30", until=None)[0], rec(hw, "--every", "60")[0], inproc(["--home", hw, "--reconcile", wsince, "--every", "60", "--csv", csv_ok])[0]
    check(r30 == r_until == r_csv == 2 and len(FAKE.seen) == seen and "--every must be at least 60" in outputs[-3] and "takes no --until" in outputs[-2] and "takes no --csv" in outputs[-1],
          f"reconcile watch 3: --every under 60, with --until or with --csv is refused: {r30} {r_until} {r_csv}")
    bad = mk_home("bad-tolerance"); write(os.path.join(bad, "config.toml"), config().replace("tolerance = 0.05", "tolerance = -1"))
    rc, out, err = rec(bad)
    check(rc == 2 and err.strip() == "refused: config.toml: [reconcile] tolerance must be a finite number, zero or above", f"reconcile config 1: a tolerance below zero is refused, naming the key: {err.strip()!r}")
    ex = siwithin.parse_toml_mini(example)
    check(ex["reconcile"] == siwithin.DEFAULT_CONFIG["reconcile"] == {"admin_key_command": "", "api_key_ids": [], "tolerance": 0.05} and ex["prices"]["cache_write_1h_factor"] == siwithin.DEFAULT_CONFIG["prices"]["cache_write_1h_factor"] == 1.6,
          "reconcile config 2: config.example.toml carries [reconcile] and cache_write_1h_factor, every value the default")
    rc, out, err = tool_cli(["--reconcile", SINCE, "--dir", PROJ])
    check(rc == 2 and "--reconcile reads records and runs nothing" in err, f"reconcile cli 1: --reconcile with --dir is refused by the parser: {err.strip()[-90:]!r}")
    FAKE.shutdown(); FAKE.server_close()


# ---- Linux: the plan and the fence's arguments with siwithin.PLATFORM forced, bubblewrap replaced by a shim -----------------------------------------------------

BINDS = ("--bind", "--ro-bind", "--bind-try", "--ro-bind-try")


def parse_bwrap(a):
    """bubblewrap's argument list as (option, values) pairs: the bind options take a source and a destination, tmpfs, dev and proc a path, the rest nothing."""
    out, i = [], 0
    while i < len(a):
        n = 2 if a[i] in BINDS else 1 if a[i] in ("--tmpfs", "--dev", "--proc") else 0
        out.append((a[i], tuple(a[i + 1:i + 1 + n]))); i += 1 + n
    return out


def linux_tests():
    L = os.path.join(TMP, "linux"); LH = os.path.join(L, "home"); LF = os.path.join(LH, ".config", siwithin.NAME); LP = os.path.join(LH, "work", "proj"); LR = os.path.join(LH, "work", "ref"); LB = os.path.join(L, "bin")
    for p in (LF, LP, LR, LB): os.makedirs(p)
    write(os.path.join(LF, "cap"), "100")
    calls, socat = os.path.join(L, "bwrap-calls.txt"), os.path.join(LB, "socat")
    write(socat, "#!/bin/sh\nexit 0\n"); os.chmod(socat, 0o755)
    bw_ok, bw_fail = os.path.join(LB, "bwrap-ok"), os.path.join(LB, "bwrap-fail")
    write(bw_ok, f"#!{sys.executable}\n" + BWSHIM.replace("@CALLS@", repr(calls)).replace("@SOCK@", repr(siwithin.PROXY_SOCK)).replace("@SOCAT@", repr(socat)))
    write(bw_fail, f"#!{sys.executable}\nimport sys\nsys.stderr.write('bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\\n'); sys.exit(1)\n")
    for p in (bw_ok, bw_fail): os.chmod(p, 0o755)
    lenv = {"HOME": LH, "PATH": "/usr/bin:/bin", "USER": "tester", "LANG": "C"}

    def as_platform(args, bw=bw_ok, sox=socat, plat="linux"):
        saved = (siwithin.PLATFORM, siwithin.BWRAP, siwithin.SOCAT, dict(os.environ), sys.stdin, sys.stdout, sys.stderr)
        siwithin.PLATFORM, siwithin.BWRAP, siwithin.SOCAT = plat, bw, sox
        os.environ.clear(); os.environ.update(lenv); sys.stdin = io.StringIO("a brief\n")
        o, e = io.StringIO(), io.StringIO(); sys.stdout, sys.stderr = o, e
        try: rc = siwithin.main(["--home", LF] + args)
        finally:
            siwithin.PLATFORM, siwithin.BWRAP, siwithin.SOCAT = saved[:3]; os.environ.clear(); os.environ.update(saved[3]); sys.stdin, sys.stdout, sys.stderr = saved[4:]
        return rc, o.getvalue(), e.getvalue()

    def listing(): return sorted(os.listdir(LF))

    group("linux: the plan, the preflight, the refusals")
    before = listing()
    rc, out, err = as_platform(["--dir", LP, "--read", LR, "--dry-run"])
    t = tokens(out); i = t.index("--") if "--" in t else -1
    check(rc == 0 and "ok     platform: Linux, bubblewrap" in out and listing() == before and not os.path.exists(os.path.join(LF, "runs")),
          f"linux 1: a dry run on Linux passes its checks, says the platform, and writes nothing: rc {rc}, {err.strip()[:100]!r}")
    check(t[0] == bw_ok and i > 0 and t[i + 1:i + 3] == ["/bin/sh", "-c"] and "TCP-LISTEN:<port>,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:" + siwithin.PROXY_SOCK + ' & exec "$0" "$@"' in t[i + 3] and t[i + 4:i + 6] == ["claude", "-p"],
          f"linux 2: the command is the fence program, its arguments, --, then the socat line with <port> and the CLI: {t[:1]} {t[i:i + 6]}")
    prof = section(out, "fence profile", "config checks"); lines = [x for x in prof.split("\n") if x]
    check(lines[0] == siwithin.FENCE_HEAD and lines[1:12] == ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", LH] and "--unshare-net" in lines and "/tmp/siwithin-proxy.sock" in lines,
          "linux 3: the dry run prints the arguments one to a line under their first line, the tree read-only, a private /tmp, the home empty, the network unshared")
    check(not any(x.startswith("(") or x.startswith(";") for x in lines) and "Library" not in prof and "--ro-bind-try" in lines and os.path.join(LH, ".cache") in lines and os.path.join(LH, ".zshrc") in lines
          and f"{LP}" in lines and f"{LR}" in lines and "deny_write (/opt, /usr/local, /mnt, /media, /srv) is redundant here: nothing outside the binds above is writable" in out,
          "linux 4: no sandbox-exec rule in the output, the Linux read_home and rc files bound back, both folders bound, deny_write named as redundant")
    check("ok     network: the run is in a namespace with no route out and may reach only the key proxy, by a Unix socket bound in and bridged by socat" in out and f"network: proxy; {siwithin.LINUX_NET_NOTE}" in out,
          "linux 5: the plan's network lines say what the namespace is and that nothing is counted")
    rc, out, err = as_platform(["--dir", LP, "--dry-run", "--network", "open"]); lines = [x for x in section(out, "fence profile", "config checks").split("\n") if x]; t = tokens(out)
    check(rc == 0 and "--unshare-net" not in lines and "/tmp/siwithin-proxy.sock" not in lines and "TCP-LISTEN" not in out.split("== fence profile ==")[0] and t[t.index("--") + 1:t.index("--") + 3] == ["claude", "-p"],
          "linux 6: --network open leaves the network shared, binds no socket and starts no bridge")
    rc, out, err = as_platform(["--dir", LP, "--dry-run", "--network", "report"])
    check(rc == 1 and "refuse network: report reads the macOS kernel's log, which Linux has no counterpart of; use proxy (the wall) or open" in out, f"linux 7: --network report is refused in the checks: rc {rc}")
    rc, out, err = as_platform(["--dir", LP, "--network", "report"]); n_listed = listing()
    check(rc == 1 and err.startswith("refused: ") and "no counterpart of" in err and listing() == before, f"linux 7b: and a real run is refused with it, writing nothing: {err.strip()[:80]!r}")
    missing = os.path.join(L, "no-bwrap")
    rc, out, err = as_platform(["--dir", LP, "--dry-run"], bw=missing)
    check(rc == 1 and f"refuse {missing} not found: install bubblewrap (apt install bubblewrap; dnf install bubblewrap)" in out, f"linux 8: bubblewrap missing is refused, the package named, in a dry run: rc {rc}")
    rc, out, err = as_platform(["--dir", LP], bw=missing)
    check(rc == 1 and "install bubblewrap (apt install bubblewrap; dnf install bubblewrap)" in err and listing() == before, "linux 8b: and in a real run, which leaves nothing behind")
    no_socat = os.path.join(L, "no-socat")
    rc, out, err = as_platform(["--dir", LP, "--dry-run"], sox=no_socat)
    check(rc == 1 and f"refuse {no_socat} not found: network = proxy bridges the run's loopback port to the key proxy with socat; install socat (apt install socat; dnf install socat), or use --network open" in out, "linux 9: network = proxy without socat is refused, the package named")
    rc, out, err = as_platform(["--dir", LP, "--dry-run", "--network", "open"], sox=no_socat)
    check(rc == 0 and "socat" not in out, "linux 9b: with --network open socat is not required")
    open(calls, "w").close()
    rc, out, err = as_platform(["--dir", LP, "--dry-run"], bw=bw_fail); before_fail = listing()
    check(rc == 1 and "refuse " + bw_fail + " said 'bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted'; bubblewrap cannot set up its namespaces here; on Ubuntu 23.10 and later unprivileged user namespaces are restricted by AppArmor, "
          "and the remedy is root's: a profile for /usr/bin/bwrap that allows userns, or sysctl kernel.apparmor_restrict_unprivileged_userns=0 for this boot; see README.md, Linux" in out and listing() == before,
          f"linux 10: a bubblewrap that cannot set up its namespaces refuses the dry run with its own last line quoted and the two remedies named, writing nothing: rc {rc}")
    rc, out, err = as_platform(["--dir", LP], bw=bw_fail)
    check(rc == 1 and "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" in err and "kernel.apparmor_restrict_unprivileged_userns" in err and listing() == before and "ok     platform" not in err,
          f"linux 10b: and a real run is refused the same way before anything is made: {err.strip()[:90]!r}")
    open(calls, "w").close(); as_platform(["--dir", LP, "--dry-run"])
    first = json.loads(open(calls).read().splitlines()[0])
    check(first == ["--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--", "/bin/true"],
          f"linux 11: the preflight is one run of bubblewrap on /bin/true with the tree, /dev, /proc and /tmp: {first}")
    rc, out, err = as_platform(["--dir", LP, "--dry-run"], plat="freebsd14")
    check(rc == 1 and "refuse " + siwithin.NAME + " needs macOS sandbox-exec or Linux bubblewrap and refuses to run on freebsd14 rather than run without a fence; see README.md, 'What it does not do'" in out, "linux 12: any other platform refuses, the message widened, the roadmap pointing at a heading that exists")
    rc, out, err = as_platform(["--dir", LP, "--dry-run"], plat="win32")
    check(rc == 1 and "refuses to run on Windows rather than run without a fence; see README.md, 'What it does not do'" in err and "## What it does not do\n" in open(os.path.join(ROOT, "README.md"), encoding="utf-8").read(),
          "linux 13: Windows refuses as before, and README.md has the heading the message names")
    saved_plat = siwithin.PLATFORM
    try:
        siwithin.PLATFORM = "linux"; cl = siwithin.load_config(LF)[0]["fence"]
        write(os.path.join(LF, "config.toml"), "[fence]\nwrite_home = []\n"); cu = siwithin.load_config(LF)[0]["fence"]; os.remove(os.path.join(LF, "config.toml"))
        siwithin.PLATFORM = "darwin"; cd = siwithin.load_config(LF)[0]["fence"]
    finally: siwithin.PLATFORM = saved_plat
    check(cl["read_home"] == [".cache", ".gitconfig", ".config/git"] and cl["write_home"] == [".cache"] and cl["deny_exec"] == ["/usr/bin/crontab", "/usr/bin/at", "/usr/bin/batch", "/usr/bin/systemd-run", "/usr/bin/xdg-open"]
          and cl["rc_files"] == siwithin.DEFAULT_CONFIG["fence"]["rc_files"] and cl["config_write"] == siwithin.DEFAULT_CONFIG["fence"]["config_write"] and cu["write_home"] == [] and cu["read_home"] == cl["read_home"]
          and cd == siwithin.DEFAULT_CONFIG["fence"] and "Library/Caches" in cd["read_home"],
          "linux 14: the [fence] defaults are keyed by platform: Linux's lists, config.toml still wins, macOS's unchanged")

    group("linux: fence_args by itself")
    S = os.path.join(L, "siw"); CD = os.path.join(S, "claude-config"); RUN = os.path.join(S, "runs", "r1"); EXE = os.path.join(L, "present-prog")
    os.makedirs(os.path.join(CD, "projects", "-a", "memory")); os.makedirs(os.path.join(CD, "projects", "-b")); os.makedirs(RUN); write(EXE, "x")
    fence = dict(siwithin.DEFAULT_CONFIG["fence"], **siwithin.LINUX_FENCE); fence.update(network="proxy", deny_exec=[EXE, os.path.join(L, "absent-prog")])
    mk = lambda **kw: siwithin.SimpleNamespace(**dict(dict(home="/h", folders=["/h/work/proj-x", "/h/work/ref"], readonly=False, siwithin_home=S, config_dir=CD, run=RUN, tmp=True, last_message=True, fence=fence,
                                                         read_extra=["/h/.local/bin", "/h/.local/share/claude"], write_extra=["/h/.local/state"], proxy_sock=True), **kw))
    c = mk(); a = siwithin.fence_args(c); pairs = parse_bwrap(a)
    at = lambda opt, *v: pairs.index((opt, tuple(v))) if (opt, tuple(v)) in pairs else None
    order = [at("--ro-bind", "/", "/"), at("--tmpfs", "/tmp"), at("--tmpfs", "/h"), at("--ro-bind-try", "/h/.cache", "/h/.cache"), at("--ro-bind-try", "/h/.zshrc", "/h/.zshrc"), at("--ro-bind-try", "/h/.local/bin", "/h/.local/bin"),
             at("--bind-try", "/h/.cache", "/h/.cache"), at("--bind-try", "/h/.local/state", "/h/.local/state"), at("--bind", "/h/work/proj-x", "/h/work/proj-x"), at("--ro-bind", "/h/work/ref", "/h/work/ref"), at("--tmpfs", S),
             at("--bind", RUN + "/tmp", RUN + "/tmp"), at("--bind", RUN + "/last-message.txt", RUN + "/last-message.txt"), at("--ro-bind", CD, CD), at("--bind", CD + "/projects", CD + "/projects"),
             at("--ro-bind", CD + "/projects/-a/memory", CD + "/projects/-a/memory"), at("--ro-bind", CD + "/projects/-h-work-proj-x/memory", CD + "/projects/-h-work-proj-x/memory"), at("--ro-bind", "/dev/null", EXE),
             at("--unshare-user"), at("--unshare-net"), at("--bind", RUN + "/proxy.sock", siwithin.PROXY_SOCK)]
    check(None not in order and order == sorted(order) and len(set(order)) == len(order) and a[:11] == ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/h"],
          f"fence_args 1: the rules come in the order bubblewrap applies them (tree, /tmp, empty home, home binds, folders, the tool's home, the run's own binds, the config directory, memory, deny_exec, namespaces, the socket): {order}")
    check(at("--tmpfs", "/h") < min(i for i, (o, v) in enumerate(pairs) if o in BINDS and v[0].startswith("/h/")) and at("--tmpfs", S) > max(i for i, (o, v) in enumerate(pairs) if o in BINDS and v[0].startswith("/h/")),
          "fence_args 2: the home's tmpfs comes before every bind into the home, the tool's home's tmpfs after all of them")
    under_s = {v[0] for o, v in pairs if o in BINDS and v[0].startswith(S + "/") and not siwithin.under(v[0], CD)}
    check(under_s == {RUN + "/tmp", RUN + "/last-message.txt", RUN + "/proxy.sock"} and not any(v[0] in (S, S + "/cap", S + "/ledger.md", S + "/runs", RUN) for o, v in pairs if o in BINDS),
          f"fence_args 3: nothing under the tool's home but the run's tmp, last-message.txt and proxy.sock is bound, besides the config directory: {sorted(under_s)}")
    cw = [at("--bind", CD + "/" + p, CD + "/" + p) for p in fence["config_write"]]
    mem = [at("--ro-bind", m, m) for m in (CD + "/projects/-a/memory", CD + "/projects/-h-work-proj-x/memory")]
    check(None not in cw and len(cw) == 16 and all(x > at("--ro-bind", CD, CD) for x in cw) and all(m > at("--bind", CD + "/projects", CD + "/projects") for m in mem) and at("--ro-bind", CD + "/projects/-b/memory", CD + "/projects/-b/memory") is None,
          "fence_args 4: each config_write path is bound after the read-only config directory, and each memory folder is bound read-only again after them (an existing one, and the run's own project's); a project with none is not given one")
    check(at("--ro-bind", "/dev/null", EXE) is not None and not any(v == ("/dev/null", os.path.join(L, "absent-prog")) for o, v in pairs) and sum(1 for o, v in pairs if v[:1] == ("/dev/null",)) == 1,
          "fence_args 5: a deny_exec path that exists is bound over with /dev/null, one that does not is left out")
    c_open = mk(fence=dict(fence, network="open"), proxy_sock=False, readonly=True); a_open = siwithin.fence_args(c_open)
    check("--unshare-net" in a and "--unshare-net" not in a_open and not any(x.endswith("proxy.sock") for x in a_open) and ("--ro-bind", ("/h/work/proj-x", "/h/work/proj-x")) in parse_bwrap(a_open)
          and ("--bind", ("/h/work/proj-x", "/h/work/proj-x")) not in parse_bwrap(a_open) and "--new-session" not in a and "--cap-add" not in " ".join(a) and "--die-with-parent" in a,
          "fence_args 6: --unshare-net only for proxy, no socket bind for open, a readonly run's first folder bound read-only, no --new-session and no capability added")
    a_odd = siwithin.fence_args(mk(folders=["/h/work/my_proj"]))
    check(not any(v and "my_proj" in v[0] and v[0].endswith("memory") for o, v in parse_bwrap(a_odd)) and sum(1 for o, v in parse_bwrap(a_odd) if v[:1] and v[0].endswith("/memory")) == 1 and siwithin.project_dir_name("/h/work/my_proj") is None
          and siwithin.project_dir_name("/h/work/proj-x") == "-h-work-proj-x",
          "fence_args 7: a folder with a character outside letters, digits, / and - is given no memory bind of its own: the CLI's name for it was not seen")
    try: siwithin.fence_args(mk(folders=["/h/work/bad\nname"])); bad = None
    except siwithin.Refused as x: bad = str(x)
    check(bad is not None and "control character" in bad, f"fence_args 8: a path with a control character is refused: {bad!r}")
    seen_before = sorted(os.listdir(CD)) + sorted(os.listdir(os.path.join(CD, "projects")))
    siwithin.fence_args(c)
    check(sorted(os.listdir(CD)) + sorted(os.listdir(os.path.join(CD, "projects"))) == seen_before and not os.path.exists(RUN + "/last-message.txt"), "fence_args 9: building the arguments creates nothing")
    siwithin.fence_prepare(c)
    check(all(os.path.isdir(CD + "/" + p) for p in fence["config_write"] if "." not in p) and all(os.path.isfile(CD + "/" + p) for p in ("history.jsonl", ".last-cleanup")) and os.path.isdir(CD + "/projects/-h-work-proj-x/memory")
          and os.path.getsize(RUN + "/last-message.txt") == 0 and os.path.isdir(CD + "/projects/-a/memory"), "fence_args 10: fence_prepare makes the state folders, the two state files empty, the run's memory folder and the last-message file")

    group("linux: the walk's marker read")
    ps_calls = os.path.join(L, "ps-calls.txt"); ps = os.path.join(LB, "ps")
    write(ps, f"#!{sys.executable}\nimport json, sys\nopen({ps_calls!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
              "if sys.argv[1:] != ['-A', '-ww', '-o', 'pid=,tty=,time=,args=', 'e']: sys.exit(64)\n"
              "print('''    1 ?        00:00:03 /sbin/init splash HOME=/root LANG=C\n"
              "  101 pts/0    00:00:00 /usr/bin/python3 x.py HOME=/h CLAUDE_CODE_TMPDIR=/r/tmp CLAUDE_CONFIG_DIR=/c TERM=x\n"
              "  102 ?        00:00:00 sleep 5 CLAUDE_CODE_TMPDIR=/r/tmp PATH=/usr/bin\n"
              " 4321 ?        01:02:03 bwrap --unshare-user --die-with-parent -- claude -p FOO=bar CLAUDE_CONFIG_DIR=/c CLAUDE_CODE_TMPDIR=/r/tmp\n"
              "  103 ?        00:00:00 sleep 6 CLAUDE_CODE_TMPDIR=/r/tmp CLAUDE_CONFIG_DIR=/cc\n"
              "  104 ?        00:00:00 sh -c 'echo CLAUDE_CODE_TMPDIR=/r/tmp'\n"
              "  105 ?        00:00:00 sleep 7 CLAUDE_CONFIG_DIR=/c LANG=C''')\n")
    os.chmod(ps, 0o755)
    saved_ps, saved_plat = siwithin.PS, siwithin.PLATFORM
    try:
        siwithin.PS, siwithin.PLATFORM = ps, "linux"
        found = siwithin.ps_marked(["CLAUDE_CODE_TMPDIR=/r/tmp", "CLAUDE_CONFIG_DIR=/c"]); one = siwithin.ps_marked(["CLAUDE_CODE_TMPDIR=/r/tmp"])
    finally: siwithin.PS, siwithin.PLATFORM = saved_ps, saved_plat
    got = [json.loads(l) for l in open(ps_calls).read().splitlines()]
    check(found == {101, 4321} and one == {101, 102, 103, 4321} and got == [["-A", "-ww", "-o", "pid=,tty=,time=,args=", "e"]] * 2,
          f"walk linux 1: with the Linux arguments ps_marked finds the pid carrying every marker and not the one carrying only one, a longer value, or the text in a command: {sorted(found)} {sorted(one)}; ps was called with {got[0]}")


# ---- Part 4, Linux only: fake CLIs inside the real bubblewrap ------------------------------------------------------------------------------------------------------

BCLAUDE = r'''
import json, os, socket, subprocess, sys, time, urllib.request
a = sys.argv[1:]
if a == ["--version"]: print("2.1.296 (fake)"); sys.exit(0)
if a == ["auth", "status"]: print(json.dumps({"loggedIn": True, "authMethod": "api_key"})); sys.exit(0)
brief = sys.stdin.read()
d = os.getcwd()  # the run's first folder: the one place besides its temp root that the fence lets this program write
def ev(o): print(json.dumps(o), flush=True)
def put(name, text):
    with open(os.path.join(d, name), "w") as f: f.write(text)
def attempt(fn):
    try: fn(); return ["ok", 0]
    except OSError as e: return [type(e).__name__, e.errno]
ev({"type": "system", "subtype": "init", "apiKeySource": "ANTHROPIC_API_KEY", "session_id": "sess-4"})
HB = """
import os, sys, time
with open(os.path.join(sys.argv[1], "hb.txt"), "a") as f:
    end = time.time() + 40
    while time.time() < end: print(repr(time.time()), file=f, flush=True); time.sleep(0.05)
"""
if "MODE:probe" in brief:
    p = json.loads(brief.split("MODE:probe ", 1)[1])
    put("probe.json", json.dumps({"marker": attempt(lambda: open(p["marker"]).read()), "w1": attempt(lambda: open(os.path.join(d, "w1.txt"), "w").write("x")),
                                  "w2": attempt(lambda: open(os.path.join(p["ro"], "w2.txt"), "w").write("x")), "tmp": attempt(lambda: open(p["tmpfile"], "w").write("x")),
                                  "cap": attempt(lambda: open(p["cap"]).read()), "etc": attempt(lambda: open("/etc/siwithin-probe", "w").write("x")),
                                  "pid": os.path.exists("/proc/%d" % p["pid"]), "proc": sorted(x for x in (os.listdir("/proc") if os.path.isdir("/proc") else []) if x.isdigit())[:5]}))
elif "MODE:wall" in brief:
    try: socket.create_connection(("1.1.1.1", 53), 2).close(); put("wall.txt", "connected")
    except OSError as e: put("wall.txt", f"{type(e).__name__} errno {e.errno} {e}")
elif "MODE:detach" in brief:
    subprocess.Popen([sys.executable, "-c", HB, d], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(200):
        if os.path.exists(os.path.join(d, "hb.txt")) and len(open(os.path.join(d, "hb.txt")).read().split("\n")) > 3: break
        time.sleep(0.02)
else:  # a request to the API as the CLI makes it: the address it was given, the token it was given
    req = urllib.request.Request(os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages", method="POST", headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "content-type": "application/json"},
                                 data=json.dumps({"model": "claude-sonnet-5-5", "max_tokens": 16, "stream": False, "messages": []}).encode())
    put("post.txt", f"{urllib.request.urlopen(req, timeout=20).status} {os.environ['ANTHROPIC_BASE_URL']}")
ev({"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "result": "part 4 done", "total_cost_usd": 0.0004, "session_id": "sess-4", "permission_denials": [],
    "modelUsage": {"claude-sonnet-5-5": {"inputTokens": 200, "outputTokens": 40, "cacheReadInputTokens": 100, "cacheCreationInputTokens": 0, "webSearchRequests": 0, "costUSD": 0.0004}}})
'''


def linux_real_tests():
    if not LINUX: print(f"Part 4 skipped: this is {sys.platform}, not Linux; the fence it tests is bubblewrap"); return
    if not os.path.exists(siwithin.BWRAP): print(f"Part 4 skipped: {siwithin.BWRAP} not found (apt install bubblewrap)"); return
    why = siwithin.bwrap_preflight()
    if why: print(f"Part 4 skipped: {why}"); return
    import http.server, signal, threading
    group("Part 4: the real bubblewrap, fake CLIs and a fake upstream")
    show[0] = True  # each check is named as it passes: this part's first run on a machine is read line by line
    have_socat = os.path.exists(siwithin.SOCAT)
    B4 = os.path.join(TMP_ROOT, "part4"); H4 = os.path.join(B4, "home"); F4 = os.path.join(H4, ".config", siwithin.NAME); BIN4 = os.path.join(H4, "bin"); D1 = os.path.join(H4, "work", "proj"); D2 = os.path.join(H4, "work", "ref")
    for p in (F4, BIN4, D1, D2): os.makedirs(p)
    write(os.path.join(F4, "cap"), "100"); write(os.path.join(H4, "marker.txt"), "outside the fence"); write(os.path.join(BIN4, "bclaude"), f"#!{sys.executable}\n" + BCLAUDE); os.chmod(os.path.join(BIN4, "bclaude"), 0o755)

    class Up(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a): pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0)); self.server.recs.append({"path": self.path, "key": self.headers.get("x-api-key")})
            out = json.dumps({"id": "msg_j", "type": "message", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 50, "output_tokens": 20}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

    UP = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Up); UP.daemon_threads = True; UP.recs = []
    threading.Thread(target=UP.serve_forever, daemon=True).start()
    write(os.path.join(F4, "config.toml"), f'[adapters.claude]\nbin = "bclaude"\n[auth]\nupstream = "http://127.0.0.1:{UP.server_address[1]}"\n')
    env = {"HOME": H4, "PATH": BIN4 + ":/usr/bin:/bin", "USER": "tester", "LANG": "C", "ANTHROPIC_API_KEY": TESTKEY}

    def run(brief, *args):
        saved = (dict(os.environ), sys.stdin, sys.stdout, sys.stderr)
        os.environ.clear(); os.environ.update(env); sys.stdin = io.StringIO(brief); o, e = io.StringIO(), io.StringIO(); sys.stdout, sys.stderr = o, e
        try: rc = siwithin.main(["--home", F4, "--dir", D1, "--read", D2, "--timeout", "60"] + list(args))
        finally: os.environ.clear(); os.environ.update(saved[0]); sys.stdin, sys.stdout, sys.stderr = saved[1:]
        runs = sorted(os.listdir(os.path.join(F4, "runs")), key=lambda n: os.stat(os.path.join(F4, "runs", n)).st_mtime_ns)
        r = os.path.join(F4, "runs", runs[-1]) if runs else None
        return rc, o.getvalue(), e.getvalue(), r, (json.load(open(os.path.join(r, "summary.json"))) if r and os.path.exists(os.path.join(r, "summary.json")) else {})

    net = [] if have_socat else ["--network", "open"]  # the bridge needs socat: without it the probes run with the network open and the wall and the bridge are not checked
    if not have_socat: print(f"Part 4: {siwithin.SOCAT} not found (apt install socat): (b) the wall and (c) the bridge are skipped, the other runs use --network open")
    tmpfile = f"/tmp/siwithin-probe-{os.getpid()}"
    # (a) a probe as the CLI
    probe = {"marker": os.path.join(H4, "marker.txt"), "ro": D2, "tmpfile": tmpfile, "cap": os.path.join(F4, "cap"), "pid": os.getpid()}
    rc, out, err, r, s = run("MODE:probe " + json.dumps(probe), *net)
    pj = json.load(open(os.path.join(D1, "probe.json"))) if os.path.exists(os.path.join(D1, "probe.json")) else {}
    check(rc == 0 and s.get("status") == "done" and pj, f"part 4 a0: the probe run is done and wrote its answers into the first folder: rc {rc}, {s.get('status')}, {err.strip()[:200]!r}, stderr.txt: {open(os.path.join(r, 'stderr.txt')).read()[-500:]!r}")
    check(pj.get("marker") == ["FileNotFoundError", 2], f"part 4 a1: a file planted in the home is not found inside: {pj.get('marker')}")
    check(pj.get("w1") == ["ok", 0] and os.path.exists(os.path.join(D1, "w1.txt")), f"part 4 a2: a write in the first folder is kept: {pj.get('w1')}")
    check(pj.get("w2", [0, 0])[1] == 30 and not os.path.exists(os.path.join(D2, "w2.txt")), f"part 4 a3: a write in the second folder, read-only, is refused (Read-only file system): {pj.get('w2')}")
    check(pj.get("tmp") == ["ok", 0] and not os.path.exists(tmpfile), f"part 4 a4: a write to /tmp is allowed inside and gone after the run: {pj.get('tmp')}, outside: {os.path.exists(tmpfile)}")
    check(pj.get("cap") == ["FileNotFoundError", 2], f"part 4 a5: the tool's own home is not there: its cap file is not found: {pj.get('cap')}")
    check(pj.get("pid") is False and pj.get("etc", [0, 0])[1] == 30, f"part 4 a6: the runner's pid is not in /proc inside ({pj.get('proc')}), and a write under /etc is refused: {pj.get('etc')}")
    check(os.path.isfile(os.path.join(r, "fence.sb")) and open(os.path.join(r, "fence.sb")).read().startswith(siwithin.FENCE_HEAD + "\n") and "outlived" in s, "part 4 a7: the run folder holds fence.sb, bubblewrap's arguments, and the summary says outlived")
    if have_socat:
        # (b) the wall
        rc, out, err, r, s = run("MODE:wall")
        wall = open(os.path.join(D1, "wall.txt")).read() if os.path.exists(os.path.join(D1, "wall.txt")) else ""
        check(rc == 0 and "errno 101" in wall and "Network is unreachable" in wall, f"part 4 b: the wall: a connect to 1.1.1.1:53 fails at once with errno 101: {wall!r}")
        # (c) the bridge
        UP.recs.clear(); n_lines = len(open(os.path.join(F4, "ledger.md")).read().strip().split("\n"))
        rc, out, err, r, s = run("MODE:basic")
        post = open(os.path.join(D1, "post.txt")).read() if os.path.exists(os.path.join(D1, "post.txt")) else ""
        check(rc == 0 and s.get("status") == "done" and post.startswith("200 http://127.0.0.1:") and [x["key"] for x in UP.recs] == [TESTKEY] and [x["path"] for x in UP.recs] == ["/v1/messages"],
              f"part 4 c1: the CLI's request to its loopback address reached the upstream outside with the real key, through socat and the Unix socket: {post!r}, upstream saw {UP.recs}, {err.strip()[:150]!r}")
        led = open(os.path.join(F4, "ledger.md")).read().strip().split("\n")
        rc2, out2, _ = tool_cli(["--verify", "--home", F4])
        check(len(led) == n_lines + 1 and "true $0.0004" in led[-1] and s.get("proxy_requests") == 1 and rc2 == 0 and TESTKEY not in open(os.path.join(r, "proxy.jsonl")).read()
              and s["network"]["note"] == siwithin.LINUX_NET_NOTE and not os.path.exists(os.path.join(r, "proxy.sock")), f"part 4 c2: the ledger line and the receipt are as on macOS, --verify passes, the socket file is gone: {led[-1][-120:]!r}")
    # (d) a detached program
    for f in ("hb.txt",):
        if os.path.exists(os.path.join(D1, f)): os.remove(os.path.join(D1, f))
    rc, out, err, r, s = run("MODE:detach", *net)
    hb = os.path.join(D1, "hb.txt"); end = time.time() + 3.5; still = True
    while time.time() < end and still:
        size = os.path.getsize(hb); time.sleep(0.5); still = os.path.getsize(hb) != size  # growing: still running
    check(rc == 0 and not still and "outlived" in s, f"part 4 d: a detached heartbeat started inside is gone within three seconds of the runner's return; outlived on record: {s.get('outlived')}")
    # (e) the network open
    UP.recs.clear()
    rc, out, err, r, s = run("MODE:basic", "--network", "open")
    post = open(os.path.join(D1, "post.txt")).read()
    check(rc == 0 and s.get("status") == "done" and [x["key"] for x in UP.recs] == [TESTKEY] and "--unshare-net" not in open(os.path.join(r, "fence.sb")).read().split("\n") and s["network"]["mode"] == "open",
          f"part 4 e: --network open: the same request reaches the upstream, and the arguments hold no --unshare-net: {post!r}")
    show[0] = False
    UP.shutdown(); UP.server_close()


try:
    # ---------------------------------------------------------------- part 1: dry runs
    write(os.path.join(FH, "cap"), "10\n")
    write(os.path.join(FH, "ledger.md"), f"# {siwithin.NAME} ledger\n"
          "2026-10-01 09:00 | a | /x | claude sonnet - | 3 turns | 1.0 min | cli $4.2500 | true $4.2500 | in 1k out 1k | runs/a | done\n"
          "2026-10-02 09:00 | b | /x | claude sonnet - | 3 turns | 1.0 min | cli $2.2500 | true $2.2500 | in 1k out 1k | runs/b | done\n")
    LINUX_OK = LINUX and os.path.exists(siwithin.BWRAP) and os.path.exists(siwithin.SOCAT) and siwithin.bwrap_preflight() is None  # a real dry run on Linux passes its checks only with bubblewrap working and socat there
    good_rc = 0 if DARWIN or LINUX_OK else 1  # elsewhere the dry run prints everything and still reports the refusal

    if not DARWIN: print("-- dry runs through the real platform: skipped, their profile lines are macOS's; the Linux plan is checked below with the platform forced")
    if DARWIN:
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
        check(f'(allow file-read* (subpath "{FH}/claude-config"))' in lines and f'(deny file-write* (subpath "{FH}/claude-config"))' in lines, "the CLI's config directory readable, and refused for writing as a whole")
        state = [i for i, x in enumerate(lines) if x.startswith("(allow file-write*") and f'(subpath "{FH}/claude-config/projects")' in x]
        check(len(state) == 1 and f'(subpath "{FH}/claude-config/sessions")' in lines[state[0]] and "claude-config/settings.json" not in lines[state[0]], "the config directory's state paths allowed back, the settings file not among them")
        check(bool(state) and lines.index(f'(deny file-write* (subpath "{FH}/claude-config"))') < state[0], "the state allow comes after the config directory's deny, so it wins")
        check(any(x.startswith("(deny file-write* (regex #") and "/projects/[^/]+/memory(/|$)" in x for x in lines), "memory folders under the transcripts refused")
        check(lines.index(f'(deny file-read* (subpath "{HOME}"))') < lines.index(f'(allow file-read* (subpath "{PROJ}"))') < lines.index(f'(deny file-read* (subpath "{FH}"))'),
              "later rules win: home deny, then folders, then the tool's home deny")
        check(any(f'(literal "{HOME}/.zshrc")' in x and x.startswith("(allow file-read*") for x in lines) and any(f'"{HOME}/Library/Keychains"' in x for x in lines), "rc files and keychain allowed back")
        check(any(x.startswith("(deny process-exec") and '"/usr/bin/osascript"' in x for x in lines), "osascript refused")
        check(".ssh" not in prof and not any(re.fullmatch(NO_FILTER, x) for x in lines), "no .ssh allowed and no rule without a filter")
        check("/Users/" not in prof.replace(HOME, ""), "no path but the temporary home in the profile")
        MARK = re.compile(r'^\(deny network\* \(with message "siwithin-net:[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}-run"\)\)$')  # the run's mark is its folder's name
        di = [i for i, x in enumerate(lines) if MARK.match(x)]
        check(len(di) == 1 and lines[di[0] + 1] == '(allow network-outbound (remote ip "localhost:<port>"))' and not any("(with report)" in x for x in lines) and lines.index("(allow default)") < di[0],
              f"network 1: by default the profile refuses every socket under the run's mark, then allows the key proxy's loopback port, shown as <port> in a dry run: {[x for x in lines if 'network' in x]}")
        check("ok     network: the run may open only the key proxy's loopback port; every other socket, DNS included, is refused by the fence" in out, "network 1b: the check line says what the wall refuses")
        rc2, out2, err2 = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "3.5", "--network", "report"])
        prof2 = section(out2, "fence profile", "config checks"); lines2 = [x for x in prof2.split("\n") if x]
        check(rc2 == good_rc and sum(1 for x in lines2 if re.fullmatch(r'\(allow \(with report\) network\* \(with message "siwithin-net:[^"]+"\)\)', x)) == 1 and not any(x.startswith("(deny network") for x in lines2)
              and "warn   network: open; every socket the run opens is reported in summary.json (network), nothing is refused: a survey, not a wall" in out2,
              f"network 2: --network report: one allow-with-report rule under the mark, no deny, and the warn: {[x for x in lines2 if 'network' in x]}")
        rc2, out2, err2 = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "3.5", "--network", "open"])
        prof2 = section(out2, "fence profile", "config checks"); lines2 = [x for x in prof2.split("\n") if x]
        check(rc2 == good_rc and not any("network" in x for x in lines2 if not x.startswith(";")) and '; the network: open and unreported ([fence] network = "open")' in lines2
              and "warn   network: open and unreported; a run can send anything it can read to any host" in out2, "network 3: --network open: no network rule, the comment in its place, and the warn")
        NH = os.path.join(TMP, "net-bad"); os.makedirs(NH); write(os.path.join(NH, "cap"), "10"); write(os.path.join(NH, "config.toml"), '[fence]\nnetwork = "wall"\n')
        rc2, out2, err2 = tool_cli(["--home", NH, "--dir", PROJ, "--dry-run", "--budget", "1"])
        check(rc2 == 1 and err2.strip() == "refused: config.toml: [fence] network must be one of proxy, report, open, not 'wall'" and "== command ==" not in out2, f"network 4: a config value outside the three is refused before anything is printed, naming the key: {err2.strip()!r}")
        rc2, out2, err2 = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "3.5"])
        lines2 = [x for x in section(out2, "fence profile", "config checks").split("\n") if x]
        check(rc2 == good_rc and any(MARK.match(x) for x in lines2), "network 4b: the next dry run on the default config is back to proxy mode")
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
        check(rc == 0 and out.strip() == "siwithin 0.6.0", f"--version prints siwithin 0.6.0: {out.strip()!r}")
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
        write(os.path.join(FH2, "cap"), "50"); write(os.path.join(FH2, "config.toml"), '[prices]\n"made-up-1" = [1.0, 1.0, 0.5, 4.0]\n[fence]\nnetwork = "open"\n')
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
        rc, out, err = tool_cli(base + ["--soft-budget", "--model", "gpt-5.3-codex", "--budget", "2", "--network", "proxy"])
        check(rc == 1 and 'refuse network: proxy ([fence] network) allows the run only the key proxy\'s port, and adapter codex has auth = "env", which starts no proxy; set network = "open" under [fence] or pass --network open' in out
              and "== command ==" in out, "network 5: codex (auth = env) under network = proxy is refused in the checks, with the way out named; the plan is still printed")
        rc, out, err = tool_cli(["--home", FH2, "--adapter", "nope", "--dir", PROJ, "--dry-run"])
        check(rc == 1 and "unknown adapter" in err, "unknown adapter refused")
    if not DARWIN and not LINUX:
        check("refuses to run on" in tool_cli(["--dir", PROJ, "--dry-run"])[1], "other platforms: the refusal and the roadmap are printed")

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
    st = siwithin.new_state("claude-haiku-5-5")
    siwithin.feed_claude(st, {"type": "assistant", "message": {"id": "m9", "usage": {"output_tokens": 8}, "content": [{"type": "text", "text": "part 32 written"}]}}, {})
    siwithin.feed_claude(st, {"type": "result", "subtype": "error_max_budget_usd", "is_error": True, "errors": ["Reached maximum budget ($0.1)"], "num_turns": 32, "total_cost_usd": 0.109, "modelUsage": {}}, {})
    check(st["failed"] == "stopped by the CLI's budget flag: Reached maximum budget ($0.1)" and st["text"] == "part 32 written" and st["text_is_last_message"], f"the CLI's budget stop is named in its own words, and the last message stands in for the missing result text: {st['failed']!r}")
    st = siwithin.new_state("claude-haiku-5-5"); siwithin.feed_claude(st, {"type": "result", "subtype": "error_max_turns", "is_error": True, "errors": ["Reached maximum number of turns (3)"], "num_turns": 3}, {})
    check(st["failed"] == "stopped by the CLI, error_max_turns: Reached maximum number of turns (3)", f"any other stop of the CLI's is named with its subtype: {st['failed']!r}")
    st = siwithin.new_state("claude-haiku-5-5"); siwithin.feed_claude(st, {"type": "result", "subtype": "error_during_execution", "is_error": True, "terminal_reason": "api_error", "api_error_status": 529, "result": "overloaded", "num_turns": 1}, {})
    check(st["failed"] == "api error 529: overloaded", f"an API failure keeps its name and status: {st['failed']!r}")
    check(siwithin.forbidden_reason("/a/B/c", "/a", [("/a/b", "x")]) is not None and siwithin.forbidden_reason("/a/bb", "/a", [("/a/b", "x")]) is None and siwithin.forbidden_reason("/", "/a", []) is not None, "forbidden_reason: case-insensitive, whole path parts, ancestors of the home")
    c = siwithin.SimpleNamespace(home="/h", folders=["/h/p"], readonly=False, siwithin_home="/h/.config/f", config_dir="/h/.config/f/c", run="/h/.config/f/runs/r", tmp=False, last_message=False,
                              fence=dict(siwithin.DEFAULT_CONFIG["fence"], write_home=[], deny_exec=[], rc_files=[]), read_extra=[], write_extra=[])
    pl = [x for x in siwithin.fence_profile(c).split("\n") if x and not x.startswith(";")]
    check(not any(re.fullmatch(NO_FILTER, x) for x in pl) and not any("process-exec" in x for x in pl), "empty lists leave no rule behind (an empty allow would allow everything)")
    check('(allow file-read-metadata (literal "/h/.config")' in " ".join(pl) or '(literal "/h/.config")' in " ".join(pl), "folders above allowed ones get metadata only")
    di = pl.index('(deny network* (with message "siwithin-net:r"))')
    check(pl[di + 1] == '(allow network-outbound (remote ip "localhost:@PROXY_PORT@"))' and siwithin.PROXY_PORT == "@PROXY_PORT@", "network 6: the builder's proxy mode: the deny under the run's mark, then the allow with the port's placeholder")
    check(siwithin.network_rules("report", "/x/runs/r2").split("\n")[-1] == '(allow (with report) network* (with message "siwithin-net:r2"))'
          and siwithin.network_rules("open", "/x/runs/r3") == '; the network: open and unreported ([fence] network = "open")', "network 7: the builder's report mode is one allow-with-report rule, its open mode a comment")
    try: siwithin.network_rules("wall", "/x/runs/r"); bad = None
    except siwithin.Refused as x: bad = str(x)
    check(bad == "[fence] network must be one of proxy, report, open, not 'wall'", f"network 8: the builder refuses a mode outside the three: {bad!r}")
    M = "siwithin-net:r"
    msgs = [f"2 duplicate reports for Sandbox: claude(100) deny(1) network-outbound remote:*:443\n{M}", f"Sandbox: claude(100) deny(1) network-outbound /private/var/run/mDNSResponder\n{M}",
            f"Sandbox: curl(101) deny(1) network-outbound remote:*:443\n{M}", f"Sandbox: claude(100) allow network-outbound remote:*:9\n{M}",
            f"log run noninteractively, parent: 1 (zsh), args: '/usr/bin/log' 'show' '--predicate' 'eventMessage CONTAINS \"{M}\"'",  # the log's own line about the read: the mark in its arguments, no second line
            f"Sandbox: claude(100) deny(1) file-read-data /etc/hosts\n{M}", f"Sandbox: claude(100) deny(1) network-outbound remote:*:443\nsiwithin-net:other"]
    nf = siwithin.network_figures("proxy", M, msgs, 100)
    check((nf["refused"], nf["reported"], nf["cli"], nf["others"], nf["unparsed"], nf["late"]) == (4, 1, 4, 1, 1, 0)
          and nf["targets"] == {"deny network-outbound remote:*:443": 3, "deny network-outbound /private/var/run/mDNSResponder": 1, "allow network-outbound remote:*:9": 1} and nf["processes"] == {"claude(100)": 4, "curl(101)": 1},
          f"network 9: the figures count a coalesced line as the N duplicates the kernel states after the plain line it logged, split the CLI's pid from the others, skip the log's own line and another run's mark, and count a line of another shape as unparsed: {nf}")
    check(siwithin.network_line(nf) == "network: proxy, refused 4 (cli 4, others 1): deny network-outbound remote:*:443 x3, allow network-outbound remote:*:9 x1, deny network-outbound /private/var/run/mDNSResponder x1",
          f"network 10: the printed line, targets by count: {siwithin.network_line(nf)!r}")
    check(siwithin.network_line(dict(nf, mode="report")).startswith("network: report, reported 1 (cli 4, others 1): ") and siwithin.network_line({"mode": "open"}) == "network: open, unreported"
          and siwithin.network_line(dict(nf, targets={}, note="the kernel's report could not be read: x")) == "network: proxy, refused 4 (cli 4, others 1); the kernel's report could not be read: x",
          "network 11: the line in report and open modes, and with a note")
    write(os.path.join(TMP, "l.md"), "# header with true $9 in it\n2026-10-01 09:00 | a | /x | y | z | true $1.5000 | done\nnot a line | true $7\n2026-10-02 09:00 | b | true $0.2500 (ceiling)\n")
    check(siwithin.ledger_total(os.path.join(TMP, "l.md")) == (1.75, 2), "ledger total counts dated lines only")

    linux_tests()

    # ---------------------------------------------------------------- part 3: whole runs against fake CLIs
    for PLAT in (["darwin"] if DARWIN else []) + ["linux"]:
        TMP = os.path.join(TMP_ROOT, "pass-" + PLAT); os.makedirs(TMP)  # a folder of its own: the pass leaves homes and copies behind that the next would meet
        group("whole runs, fake CLIs" + (", Linux: siwithin.PLATFORM forced, the bubblewrap shim" if PLAT == "linux" else ""))
        E = os.path.join(TMP, "e2e"); EH = os.path.join(E, "home"); EF = os.path.join(EH, ".config", siwithin.NAME); BIN = os.path.join(E, "bin"); ED = os.path.join(EH, "proj")
        for p in (EF, BIN, ED): os.makedirs(p)
        write(os.path.join(EF, "cap"), "100")
        # these fakes make no API requests, so their runs are 0.2.1's: the key in the environment (auth = "env"); the proxy's runs are further down, in their own home
        write(os.path.join(EF, "config.toml"), '[adapters.claude]\nauth = "env"\nenv_pass = ["ANTHROPIC_API_KEY", "FAKE_AUTH"]   # the fake CLI is told how to answer through a listed variable\n[fence]\nnetwork = "open"   # auth = env starts no proxy, so the network stays as it was\n')
        shim =os.path.join(BIN, "sandbox-shim")
        write(shim, f"#!{sys.executable}\nimport os, sys\nassert sys.argv[1] == '-f' and os.path.isfile(sys.argv[2])\nos.execv(sys.argv[3], sys.argv[3:])\n")
        bwshim, socat_dummy, bw_calls = os.path.join(BIN, "bwrap-shim"), os.path.join(BIN, "socat-dummy"), os.path.join(E, "bwrap-calls.txt")
        write(bwshim, f"#!{sys.executable}\n" + BWSHIM.replace("@CALLS@", repr(bw_calls)).replace("@SOCK@", repr(siwithin.PROXY_SOCK)).replace("@SOCAT@", repr(socat_dummy)))
        write(socat_dummy, "#!/bin/sh\nexit 0\n")  # SOCAT only has to exist: the shim strips the line that would start it
        logshim = os.path.join(BIN, "log-shim")  # stands in for /usr/bin/log: a fake run leaves nothing in the kernel's report, so canned lines under the run's mark come back, the CLI's pid on them
        write(logshim, f"#!{sys.executable}\n" + LOGSHIM.replace("@CALLS@", repr(os.path.join(E, "log-calls.txt"))).replace("@EH@", repr(EH)))
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
if "MODE:clibudget" in brief:  # the CLI's own budget flag stops the run: a result with is_error, errors, and no result text
    ev({{"type": "assistant", "message": {{"id": "msg_C", "model": "claude-sonnet-5-5", "usage": {{"input_tokens": 1000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 8, "service_tier": "standard"}}, "content": [{{"type": "text", "text": "last words before the stop"}}]}}}})
    ev({{"type": "result", "subtype": "error_max_budget_usd", "is_error": True, "num_turns": 3, "errors": ["Reached maximum budget ($0.5)"], "total_cost_usd": 0.5, "session_id": "sess-1",
        "modelUsage": {{"claude-sonnet-5-5": {{"inputTokens": 100000, "outputTokens": 10000, "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0, "webSearchRequests": 0, "costUSD": 0.5}}}}, "permission_denials": []}})
    sys.exit(1)
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
        for p in ("sandbox-shim", "bwrap-shim", "socat-dummy", "log-shim", "claude", "codex"): os.chmod(os.path.join(BIN, p), 0o755)
        write(os.path.join(BIN, "fake-ps"), f"#!{sys.executable}\n" + FAKE_PS); os.chmod(os.path.join(BIN, "fake-ps"), 0o755)
        REAL_PS = ps_works(PS_PATH)  # every run below looks at the process table: with no working ps each would carry a note
        FORCED = DARWIN and PLAT == "linux"  # macOS's ps cannot be trusted with procps's arguments: the stand-in answers them from the real process table
        siwithin.PS = os.path.join(BIN, "fake-ps") if (not REAL_PS or FORCED) else PS_PATH
        print("   (the kill walk's checks run against " + ("the real ps)" if siwithin.PS == PS_PATH else f"a stand-in for ps, because " + ("the real one is macOS's and the pass is Linux's" if REAL_PS else "the real one cannot be run here") + f"; the stand-in works: {ps_works(siwithin.PS)})"))
        saved_env, saved_stdin, saved_sb, saved_log = dict(os.environ), sys.stdin, siwithin.SANDBOX_EXEC, (siwithin.LOG_BIN, siwithin.LOG_WAIT)
        saved_plat = (siwithin.PLATFORM, siwithin.BWRAP, siwithin.SOCAT)
        SECRET = "sk-test-NOT-A-REAL-KEY-12345"

        def whole(args, brief="do the thing\n", extra_env=None):
            env = {"HOME": EH, "PATH": BIN + ":/usr/bin:/bin", "USER": "t", "ANTHROPIC_API_KEY": SECRET, "CODEX_API_KEY": SECRET, "UNLISTED_VARIABLE": "x", **(extra_env or {})}
            os.environ.clear(); os.environ.update({k: v for k, v in env.items() if v is not None})  # a None in extra_env leaves the variable out
            sys.stdin = io.StringIO(brief); siwithin.SANDBOX_EXEC = shim; siwithin.LOG_BIN, siwithin.LOG_WAIT = logshim, 0
            if PLAT == "linux": siwithin.PLATFORM, siwithin.BWRAP, siwithin.SOCAT = "linux", bwshim, socat_dummy
            o, e = io.StringIO(), io.StringIO(); so, se = sys.stdout, sys.stderr; sys.stdout, sys.stderr = o, e
            try: rc = siwithin.main(args)
            finally:
                sys.stdout, sys.stderr = so, se; os.environ.clear(); os.environ.update(saved_env); sys.stdin = saved_stdin; siwithin.SANDBOX_EXEC = saved_sb; siwithin.LOG_BIN, siwithin.LOG_WAIT = saved_log
                siwithin.PLATFORM, siwithin.BWRAP, siwithin.SOCAT = saved_plat
            return rc, o.getvalue(), e.getvalue()

        def last_run(home=EF):
            runs = sorted(os.listdir(os.path.join(home, "runs")), key=lambda n: os.stat(os.path.join(home, "runs", n)).st_mtime_ns)  # by time: "-run-10" sorts before "-run-9" by name
            r = os.path.join(home, "runs", runs[-1])
            return r, json.load(open(os.path.join(r, "summary.json")))

        def ledger(home=EF): return open(os.path.join(home, "ledger.md")).read().strip().split("\n")

        def bare(line): return re.sub(r" \| receipt [0-9a-f]{64}$", "", line)  # the line as it was before the receipt field, the status last

        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--name", "first run!", "--out", "out/result.txt", "--done", "DONE-MARKER", "--absent", "TODO"])
        r, s = last_run()
        check(rc == 0 and s["status"] == "done", f"claude run done: rc {rc}, {s.get('status')}, {err}")
        check(abs(s["true_cost"] - 0.30) < 1e-9 and s["cli_cost"] == 0.3 and s["turns"] == 3 and s["tokens_in"] == 100000 and s["tokens_out"] == 10000, f"cost, turns, tokens in the summary: {s}")
        check(s["key_source"] == "ANTHROPIC_API_KEY" and s["session_id"] == "sess-1" and s["cli_version"] == "2.1.296" and not s["notes"], f"key source, session, CLI version, no notes: {s['notes']}")
        check(s["network"] == {"mode": "open", "mark": None, "refused": 0, "reported": 0, "targets": {}, "processes": {}, "cli": 0, "others": 0, "unparsed": 0, "late": 0, "note": "unreported"} and "network: open, unreported" in out
              and ('; the network: open and unreported ([fence] network = "open")' in open(os.path.join(last_run()[0], "fence.sb")).read() if PLAT == "darwin"
                   else open(os.path.join(last_run()[0], "fence.sb")).read().startswith(siwithin.FENCE_HEAD + "\n--ro-bind\n/\n/\n") and "--unshare-net" not in open(os.path.join(last_run()[0], "fence.sb")).read().split("\n"))
              and "network: open\n" in open(os.path.join(last_run()[0], "command.txt")).read()
              and not os.path.exists(os.path.join(E, "log-calls.txt")), f"network 13: an auth = env home with network = open: the comment in fence.sb, no read of the kernel's report, the figures say unreported: {s.get('network')}")
        check(s["contract"] == {"done": {"text": "DONE-MARKER", "found": True}, "absent": {"text": "TODO", "found": False}}, "--done found, --absent not found")
        check(open(os.path.join(ED, "out", "result.txt")).read() == "All good. DONE-MARKER" and open(os.path.join(r, "result.md")).read() == "All good. DONE-MARKER", "--out written inside --dir, result.md written")
        check(all(os.path.exists(os.path.join(r, f)) for f in ("brief.md", "command.txt", "events.jsonl", "stderr.txt", "result.md", "summary.json", "fence.sb")) and r.endswith("-first-run"), "the run folder holds the record")
        check(len(open(os.path.join(r, "events.jsonl")).read().strip().split("\n")) == 5, "events.jsonl holds the CLI's events")
        check(s["stream_cost"] == 0.4502, f"the summary holds what the stream priced: {s['stream_cost']}")
        L = ledger()
        check(len(L) == 2 and L[0].startswith("# ") and re.search(r"\| first-run \| .*\| claude sonnet - \| 3 turns \| .* min \| cli \$0\.3000 \| true \$0\.3000 \| in 100k out 10k \| runs/.*-first-run \| done \| receipt [0-9a-f]{64}$", L[1]), f"one ledger line: {L[-1]}")
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
        rc, out, err = whole(["--dir", ED, "--model", "sonnet", "--budget", "0.5"], brief="MODE:clibudget")
        r, s = last_run(); STOPPED = "stopped by the CLI's budget flag: Reached maximum budget ($0.5)"
        check(rc == 1 and s["status"] == STOPPED and out.startswith(f"{siwithin.NAME} {STOPPED} | claude sonnet -"), f"the CLI's own budget stop is named, not called an api error: {s['status']!r}")
        check(bare(ledger()[-1]).endswith(f"| {STOPPED}") and "cli $0.5000" in ledger()[-1], f"the ledger line carries the CLI's stop: {ledger()[-1]}")
        check(open(os.path.join(r, "result.md")).read() == "last words before the stop" and any("result carried no text" in n for n in s["notes"]), f"result.md holds the last message when the CLI's result has no text, and the notes say so: {s['notes']}")
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
        check(bare(ledger()[-1]).endswith(f"| {KILLED}") and "true $0.5502" in ledger()[-1] and "cli $-" in ledger()[-1], f"the ledger line says it was killed for the budget: {ledger()[-1]}")
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

        group("receipts")
        sha = lambda p: siwithin.sha256_file(p)
        TAIL = re.compile(r" \| receipt ([0-9a-f]{64})$")
        carried = [(TAIL.search(l).group(1), re.search(r"\| runs/([^|]+?) \|", l).group(1)) for l in ledger() if TAIL.search(l)]
        recs = [json.load(open(os.path.join(EF, "runs", n, "receipt.json"), encoding="utf-8")) for _, n in carried]
        N_R = len(carried)
        check(N_R >= 2 and N_R == len(ledger()) - 1 and all(sha(os.path.join(EF, "runs", n, "receipt.json")) == hx for hx, n in carried),
              f"every ledger line of the home carries a receipt, {N_R} of them, and the hex on each is the sha256 of its receipt.json")
        check(recs[0]["previous"] is None and all(recs[i]["previous"] == carried[i - 1][0] for i in range(1, N_R)), "the first receipt's previous is null, each later one's is the hex on the previous line")
        check(all(sorted(r["files"]) == sorted(siwithin.RECEIPT_FILES) and len(r["files"]) == 7 and all(sha(os.path.join(EF, "runs", n, f)) == r["files"][f] for f in r["files"])
                  for r, (_, n) in zip(recs, carried)), "files holds exactly the seven names, and each hash matches the file on disk")
        r0 = recs[0]
        check(r0["receipt"] == 1 and r0["tool"] == "siwithin 0.6.0" and r0["run"] == carried[0][1] and r0["status"] == "done" and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", r0["started"]) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", r0["ended"])
              and r0["started"] <= r0["ended"] and re.fullmatch(r"[0-9a-f]{64}", r0["ledger_before"]) and sorted(r0) == ["ended", "files", "ledger_before", "previous", "receipt", "run", "started", "status", "tool"],
              f"the first receipt's fields: {r0}")
        raw0 = open(os.path.join(EF, "runs", carried[0][1], "receipt.json"), "rb").read()
        check(raw0 == (json.dumps(r0, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8"), "receipt.json is the canonical JSON, sorted keys, indent 1, a newline last")
        header = ledger()[0] + "\n"
        check(r0["ledger_before"] == hashlib.sha256(header.encode("utf-8")).hexdigest(), "the first receipt's ledger_before is the hash of the header line alone")
        summaries = {n: json.load(open(os.path.join(EF, "runs", n, "summary.json"))) for n in os.listdir(os.path.join(EF, "runs"))}
        refused = [n for n, s in summaries.items() if s["status"].startswith("refused:")]
        keyed = [n for n, s in summaries.items() if s["status"].startswith("killed: key source is 'none'")]
        check(len(refused) == 1 and not os.path.exists(os.path.join(EF, "runs", refused[0], "receipt.json")) and not any(n == refused[0] for _, n in carried), "a run refused before launch has no receipt.json and no ledger line")
        check(len(keyed) == 1 and os.path.exists(os.path.join(EF, "runs", keyed[0], "receipt.json")) and any(n == keyed[0] for _, n in carried), "the MODE:wrongkey run was killed after launch, so it is booked and has a receipt")
        rc, out, err = tool_cli(["--verify", "--home", EF]); vl = out.strip().split("\n")
        check(rc == 0 and len(vl) == N_R + 1 and all(l.startswith("ok ") for l in vl[:-1]) and vl[-1] == f"{N_R} receipts ok, 0 failed, 0 lines without a receipt", f"--verify on the home: rc {rc}, {vl[-1]!r}")

        def copy_home(tag):
            dst = os.path.join(TMP, "copy-" + tag); shutil.copytree(EF, dst); return dst

        C1 = copy_home("result"); name = carried[0][1]; p = os.path.join(C1, "runs", name, "result.md")
        b = bytearray(open(p, "rb").read()); b[0] ^= 1; open(p, "wb").write(bytes(b))
        rc, out, err = tool_cli(["--verify", "--home", C1])
        check(rc == 1 and any(l.startswith(f"FAIL {name}:") and "result.md" in l for l in out.split("\n")) and out.count("FAIL") == 1 and f"{N_R - 1} receipts ok, 1 failed" in out, f"one byte of a result.md changed: {out!r}")
        C2 = copy_home("cost"); lp = os.path.join(C2, "ledger.md"); L2 = open(lp).read().split("\n")
        i = [k for k, l in enumerate(L2) if f"runs/{carried[0][1]} |" in l][0]
        L2[i] = re.sub(r"true \$[0-9.]+", "true $0.0001", L2[i]); open(lp, "w").write("\n".join(L2))
        rc, out, err = tool_cli(["--verify", "--home", C2]); vl = out.split("\n")
        check(rc == 1 and any(l.startswith(f"FAIL {carried[0][1]}:") and "true $" in l for l in vl) and any(l.startswith(f"FAIL {carried[1][1]}:") and "ledger_before" in l for l in vl), f"the true $ of an earlier line edited: that line and the next fail: {out!r}")
        C3 = copy_home("hex"); lp = os.path.join(C3, "ledger.md"); t = open(lp).read()
        open(lp, "w").write(t.replace(carried[-1][0], "ab" * 32))
        rc, out, err = tool_cli(["--verify", "--home", C3])
        check(rc == 1 and any(l.startswith(f"FAIL {carried[-1][1]}:") for l in out.split("\n")) and out.count("FAIL") == 1, f"the last line's hex replaced: {out!r}")

        OLD = os.path.join(EH, ".config", "siwithin-old"); os.makedirs(OLD)
        write(os.path.join(OLD, "cap"), "100"); write(os.path.join(OLD, "config.toml"), open(os.path.join(EF, "config.toml")).read())
        write(os.path.join(OLD, "ledger.md"), f"# {siwithin.NAME} ledger\n2026-09-01 09:00 | old | /x | claude sonnet - | 3 turns | 1.0 min | cli $1.0000 | true $1.0000 | in 1k out 1k | runs/old | done\n")
        old_bytes = open(os.path.join(OLD, "ledger.md"), "rb").read()
        rc, out, err = whole(["--home", OLD, "--dir", ED, "--model", "sonnet"])
        shown = re.search(r"\nsession: .*\nreceipt: ([0-9a-f]{64})\n", out)
        check(rc == 0 and shown and TAIL.search(open(os.path.join(OLD, "ledger.md")).read().strip().split("\n")[-1]).group(1) == shown.group(1),
              f"a run in a home with an older ledger: the receipt line follows the session line and is the hex on the ledger line: {err}")
        rc, out, err = tool_cli(["--verify", "--home", OLD])
        check(rc == 0 and out.strip().split("\n")[-1] == "1 receipts ok, 0 failed, 1 lines without a receipt", f"a ledger from before receipts: its line counted, not failed: {out!r}")
        orun = os.path.join(OLD, "runs", os.listdir(os.path.join(OLD, "runs"))[0]); orec = json.load(open(os.path.join(orun, "receipt.json")))
        check(orec["previous"] is None and orec["ledger_before"] == hashlib.sha256(old_bytes).hexdigest(), "the first receipt after old lines: previous null, ledger_before the old ledger's hash")

        rc, out, err = tool_cli(["--verify", os.path.join(EF, "runs", carried[0][1])])
        check(rc == 0 and out.strip() == f"ok {carried[0][1]}: 7 files match the receipt", f"--verify on a run folder: {out!r}")
        rc, out, err = tool_cli(["--verify", os.path.join(C1, "runs", name)])
        check(rc == 1 and out.startswith(f"FAIL {name}:") and "result.md" in out, f"--verify on a tampered run folder: {out!r}")
        rc, out, err = tool_cli(["--verify", os.path.join(EF, "runs", refused[0])])
        check(rc == 1 and out.startswith("no receipt in "), f"--verify on a folder with no receipt: {out!r}")
        NOHOME = os.path.join(TMP, "nohome"); os.makedirs(NOHOME)
        rc, out, err = tool_cli(["--verify", "--home", NOHOME])
        check(rc == 1 and out.startswith("no ledger at ") and out.strip().endswith(os.path.join(NOHOME, "ledger.md")), f"--verify with no ledger: {out!r}")

        group("the walls: the verifier")
        show[0] = True
        first_line = [k for k, l in enumerate(open(os.path.join(EF, "ledger.md")).read().split("\n"), 1) if TAIL.search(l)][0]
        last = carried[-1][0]
        rc, out, err = tool_cli(["--verify", "--home", EF, "--expect", last]); vl = out.strip().split("\n")
        check(rc == 0 and vl[-1] == f"{N_R} receipts ok, 0 failed, 0 lines without a receipt" and "FAIL" not in out, f"verify 1: --expect with the last receipt's hash passes: {vl[-1]!r}")
        wrong = "ab" * 32
        rc, out, err = tool_cli(["--verify", "--home", EF, "--expect", wrong]); vl = out.strip().split("\n")
        check(rc == 1 and vl[-2] == f"FAIL: the last receipt is {last}, not {wrong}" and vl[-1] == f"{N_R} receipts ok, 0 failed, 0 lines without a receipt", f"verify 2: --expect with another hash fails, exit 1: {vl[-2:]}")
        V1 = copy_home("bare-after"); lp = os.path.join(V1, "ledger.md")
        with open(lp, "a") as f: f.write("2026-10-15 09:00 | sneaked | /x | claude sonnet - | 3 turns | 1.0 min | cli $1.0000 | true $0.0001 | in 1k out 1k | runs/sneaked | done\n")
        n_line = len(open(lp).read().strip().split("\n"))
        rc, out, err = tool_cli(["--verify", "--home", V1]); vl = out.strip().split("\n")
        check(rc == 1 and f"FAIL line {n_line}: no receipt, after line {first_line} had one" in vl and vl[-1] == f"{N_R} receipts ok, 1 failed, 0 lines without a receipt",
              f"verify 3: a bare line after a receipt fails, with its line number and the first receipt's: {vl[-2:]}")
        V2 = copy_home("stripped-last"); lp = os.path.join(V2, "ledger.md"); L3 = open(lp).read().rstrip("\n").split("\n")
        L3[-1] = TAIL.sub("", L3[-1]); open(lp, "w").write("\n".join(L3) + "\n")
        rc, out, err = tool_cli(["--verify", "--home", V2]); vl = out.strip().split("\n")
        check(rc == 1 and f"FAIL line {len(L3)}: no receipt, after line {first_line} had one" in vl and vl[-1].startswith(f"{N_R - 1} receipts ok, 1 failed"), f"verify 4: the receipt stripped from the last line fails: {vl[-2:]}")
        V3 = copy_home("cut-tail"); lp = os.path.join(V3, "ledger.md"); L4 = open(lp).read().rstrip("\n").split("\n")
        open(lp, "w").write("\n".join(L4[:-1]) + "\n")
        rc, out, err = tool_cli(["--verify", "--home", V3]); rc_e, out_e, _ = tool_cli(["--verify", "--home", V3, "--expect", last])
        check(rc == 0 and rc_e == 1 and f"FAIL: the last receipt is {carried[-2][0]}, not {last}" in out_e, f"verify 5: a ledger cut at its end passes alone and fails against the hash kept elsewhere: {out_e.strip().split(chr(10))[-2]!r}")
        V4 = copy_home("no-receipts"); lp = os.path.join(V4, "ledger.md")
        open(lp, "w").write("\n".join(TAIL.sub("", l) for l in open(lp).read().rstrip("\n").split("\n")) + "\n")
        rc, out, err = tool_cli(["--verify", "--home", V4]); rc_e, out_e, _ = tool_cli(["--verify", "--home", V4, "--expect", last])
        check(rc == 0 and rc_e == 1 and f"FAIL: the last receipt is none, not {last}" in out_e, "verify 6: a ledger with every receipt stripped passes alone, the 0.1 ledger's shape, and fails against the hash kept elsewhere")
        V5 = os.path.join(TMP, "copy-old-then-bare"); shutil.copytree(OLD, V5); lp = os.path.join(V5, "ledger.md")
        with open(lp, "a") as f: f.write("2026-10-15 09:00 | sneaked | /x | y | runs/sneaked | done\n")
        rc, out, err = tool_cli(["--verify", "--home", V5]); vl = out.strip().split("\n")
        check(rc == 1 and vl[-1] == "1 receipts ok, 1 failed, 1 lines without a receipt" and "FAIL line 4: no receipt, after line 3 had one" in vl,
              f"verify 7: bare lines before the first receipt are the 0.1 ledger's and stay counted; one after it fails: {vl[-2:]}")
        rc, out, err = tool_cli(["--verify", os.path.join(EF, "runs", carried[0][1]), "--expect", last])
        check(rc == 2 and "--expect goes with --verify alone" in err, f"verify 8: --expect with a run folder is a usage error: {err.strip()[-90:]}")
        rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--expect", last])
        check(rc == 2, "verify 9: --expect without --verify is a usage error")

        group("the walls: finite money")
        for bad in ("nan", "inf", "-inf"):
            rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", f"--budget={bad}"])  # the = form: argparse reads "-inf" after a space as another option
            check(rc == 1 and err.strip() == "refused: --budget must be a finite number above zero" and "== command ==" not in out, f"money 1: --budget {bad} is refused, even in a dry run: {err.strip()!r}")
        rc, out, err = whole(["--dir", ED, "--budget", "nan"]); n_lines = len(ledger())
        check(rc == 1 and err.strip() == "refused: --budget must be a finite number above zero" and len(ledger()) == n_lines, "money 1b: a real run with --budget nan is refused before launch")
        for bad in ("nan", "inf", "-inf", "-1"):
            MH = os.path.join(TMP, "cap-" + bad); os.makedirs(MH); write(os.path.join(MH, "cap"), bad + "\n")
            rc, out, err = tool_cli(["--home", MH, "--dir", PROJ, "--dry-run"]); rc2, out2, err2 = tool_cli(["--home", MH, "--dir", PROJ, "--budget", "1"])
            want = f"refused: cap in {os.path.join(MH, 'cap')} must be a finite number, zero or above"
            check(rc == 1 and err.strip() == want and "== command ==" not in out and rc2 == 1 and err2.strip() == want, f"money 2: a cap file holding {bad} is refused before launch, dry run or not: {err.strip()[:100]!r}")
        MH = os.path.join(TMP, "cap-zero"); os.makedirs(MH); write(os.path.join(MH, "cap"), "0\n")
        rc, out, err = tool_cli(["--home", MH, "--dir", PROJ, "--dry-run"])
        check(rc == 1 and "passes the cap $0.00" in out and "must be a finite" not in err, "money 3: a cap of zero is a number: the usual refusal, from the arithmetic")
        MH = os.path.join(TMP, "budget-nan"); os.makedirs(MH); write(os.path.join(MH, "cap"), "100"); write(os.path.join(MH, "config.toml"), "[defaults]\nbudget = nan\n")
        rc, out, err = tool_cli(["--home", MH, "--dir", PROJ, "--dry-run"]); rc2, out2, err2 = tool_cli(["--home", MH, "--dir", PROJ, "--dry-run", "--budget", "1"])
        check(rc == 1 and err.strip() == f"refused: [defaults] budget in {os.path.join(MH, 'config.toml')} must be a finite number above zero" and rc2 == good_rc,
              f"money 4: a default budget of nan in config.toml is refused, naming the file, unless --budget replaces it: {err.strip()[:110]!r}")
        for bad in ("0", "-2"):
            rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--budget", bad])
            check(rc == 1 and "--budget, --turns and --timeout must be above zero" in err, f"money 5: --budget {bad} keeps today's refusal")

        if PLAT == "darwin":  # the real dry run, a subprocess on the real platform
            group("the walls: deny_exec")
            rc, out, err = tool_cli(["--dir", PROJ, "--dry-run", "--budget", "1"])
            lines = [x for x in section(out, "fence profile", "config checks").split("\n") if x]
            exec_rule = [x for x in lines if x.startswith("(deny process-exec")]
            NEW_EXEC = ("/bin/launchctl", "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/batch")
            check(len(exec_rule) == 1 and all(f'(literal "{p}")' in exec_rule[0] for p in NEW_EXEC + ("/usr/bin/osascript", "/usr/bin/open")) and siwithin.DEFAULT_CONFIG["fence"]["deny_exec"][-4:] == list(NEW_EXEC),
                  f"deny 1: the fence profile carries launchctl, crontab, at and batch beside the five it had: {exec_rule}")
            check(siwithin.parse_toml_mini(example)["fence"]["deny_exec"] == siwithin.DEFAULT_CONFIG["fence"]["deny_exec"] and siwithin.parse_toml_mini(example)["auth"]["paths"] == ["/v1/messages", "/v1/messages/count_tokens"],
                  "deny 2: config.example.toml lists the same programs and the same [auth] paths as the built-in defaults")
        show[0] = False

        group("the walls: red briefs, scorer proven")
        rr = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "red", "run.py"), "--fake"], capture_output=True, text=True, timeout=120)
        tail = rr.stdout.strip().split("\n")
        check(rr.returncode == 0 and tail[-1] == "PASS" and "-- env-key" in rr.stdout and "-- outlive" in rr.stdout and "-- net-out" in rr.stdout and "FAIL" not in rr.stdout, f"red 1: tests/red/run.py --fake passes with its env-key and outlive cases: {tail[-2:]}")
        print("   (" + [l for l in tail if "checks passed" in l][-1].strip() + " in the red scorer)" if any("checks passed" in l for l in tail) else "")
        proxy_tests(whole, last_run, ledger, EH, ED, BIN)
        walk_tests(whole, last_run, EH, ED, BIN)
    show[0] = True
    try: reconcile_tests()
    finally: show[0] = False
    linux_real_tests()
finally:
    shutil.rmtree(TMP_ROOT, ignore_errors=True)

print(f"\n{count - len(failures)} of {count} checks passed" + ("" if DARWIN else " (macOS-only checks skipped)"))
if failures:
    print("FAILED: " + "; ".join(failures)); sys.exit(1)
print("PASS")
