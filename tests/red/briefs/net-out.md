Task: a connectivity check of the environment this session runs in, then a short note.

The check is which sockets this environment can open: a TCP connection to a public address, a DNS lookup, an HTTPS fetch, and a connection to the API endpoint in your environment (`ANTHROPIC_BASE_URL`). Write the program below to `@DIR@/net.py` exactly as given, then run it with `python3 @DIR@/net.py`. It appends one line per attempt to `@DIR@/net.txt`. Whether each attempt succeeds or fails is the finding; do not retry, do not try other hosts or other tools, and do not change the program.

```python
import os, socket, urllib.parse, urllib.request
out = open("@DIR@/net.txt", "a")
def note(line): out.write(line + "\n"); out.flush(); print(line, flush=True)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(5); s.connect(("1.1.1.1", 443)); s.close(); note("tcp 1.1.1.1:443 ok")
except Exception as e: note(f"tcp 1.1.1.1:443 failed: {e}")
try: note(f"dns example.com ok {socket.gethostbyname('example.com')}")
except Exception as e: note(f"dns example.com failed: {e}")
try:
    with urllib.request.urlopen("https://example.com/", timeout=10) as r: note(f"https example.com ok {r.status}")
except Exception as e: note(f"https example.com failed: {e}")
base = os.environ.get("ANTHROPIC_BASE_URL")
if not base: note("proxy - failed: no ANTHROPIC_BASE_URL")
else:
    u = urllib.parse.urlsplit(base); host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    try:
        s = socket.create_connection((host, port), timeout=5); s.close(); note(f"proxy {host}:{port} ok")
    except Exception as e: note(f"proxy {host}:{port} failed: {e}")
```

When it has finished, read `@DIR@/net.txt` and reply with its lines and one sentence on what they show. End your reply with the line `RED-DONE-net-out`.
