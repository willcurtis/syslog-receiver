#!/usr/bin/env python3
"""
syslog-tui.py — TUI syslog collector (UDP/TCP/TLS) with live, colorised view.

Features
- Listens on UDP and/or TCP (configurable ports); optional TLS for TCP (server-side)
- Parses RFC3164 and RFC5424; auto-detects RFC6587 octet-counted vs LF-delimited framing on TCP
- Colour by severity; live scroll; pause/clear; severity threshold filter
- Simple stats (total & per-severity counts)
- IPv4 and IPv6 (bind to specific addresses if needed)
- No third-party dependencies; Python 3.8+

Key bindings
- q: quit
- p: pause/resume
- c: clear messages
- [: raise severity threshold (show more severe only)
- ]: lower severity threshold (show more, including less severe)
- h or ?: help overlay

Example
  python3 syslog-tui.py --udp-port 5514 --tcp-port 10514
  python3 syslog-tui.py --tcp-port 6514 --tls --certfile server.crt --keyfile server.key
"""
import argparse
import queue
import socket
import ssl
import sys
import threading
import time
import traceback
from datetime import datetime
import curses
from curses import ascii

# ---------- Syslog parsing ----------

SEVERITY_NAMES = ["EMERG","ALERT","CRIT","ERR","WARN","NOTICE","INFO","DEBUG"]
FACILITY_NAMES = [
    "kern","user","mail","daemon","auth","syslog","lpr","news","uucp","cron","authpriv","ftp",
    "ntp","audit","alert","clock","local0","local1","local2","local3","local4","local5","local6","local7"
]

def parse_pri(line: bytes):
    # PRI is <n> at the start
    if not line.startswith(b"<"):
        return None
    try:
        end = line.index(b">", 1)
    except ValueError:
        return None
    try:
        n = int(line[1:end].decode("ascii"))
    except Exception:
        return None
    facility = n // 8
    severity = n % 8
    rest = line[end+1:]
    return facility, severity, rest

def detect_5424(rest: bytes) -> bool:
    # RFC5424: VERSION is an integer (usually 1) followed by space, then TIMESTAMP
    # Example: b"1 2025-08-15T12:34:56.123+01:00 host app procid msgid [sd] msg"
    # Accept if starts with b"1 " or b"0 " (future?); strictly it's non-zero, but we'll be lenient.
    return len(rest) >= 2 and rest[:1].isdigit() and rest[1:2] == b" "

def parse_3164(rest: bytes):
    # "Mmm dd hh:mm:ss host tag: msg"
    # We'll do a best-effort parse for display.
    try:
        parts = rest.split(b" ", 4)  # month, day, time, host, rem
        if len(parts) < 5:
            return None
        month, day, hms, host, rem = parts
        ts_str = b" ".join([month, day, hms]).decode(errors="replace")
        hostname = host.decode(errors="replace")
        msg = rem.decode(errors="replace")
        return {"ts": ts_str, "host": hostname, "app": "", "msg": msg}
    except Exception:
        return None

def parse_5424(rest: bytes):
    # "<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG"
    # We'll parse minimal fields for display.
    try:
        # split first 7 fields then the rest is MSG
        # SD can be '-' or bracketed; MSG can contain spaces.
        items = rest.split(b" ", 6)
        if len(items) < 7:
            return None
        version, ts, host, app, procid, msgid, tail = items
        # tail starts with SD then space then MSG; SD can be '-'
        sd, msg = None, ""
        if tail.startswith(b"- "):
            sd = "-"
            msg = tail[2:].decode(errors="replace")
        elif tail.startswith(b"["):
            # find matching SD block(s) end; SD may contain spaces and additional blocks
            # We'll take a simple approach: SD ends at first space after last closing bracket if any
            # If SD has multiple blocks, they are contiguous like ][
            # We scan until SD balanced (rough heuristic)
            idx = 0
            depth = 0
            for i, ch in enumerate(tail):
                if ch == 91:   # '['
                    depth += 1
                elif ch == 93: # ']'
                    if depth > 0:
                        depth -= 1
                elif ch == 32 and depth == 0: # space outside SD
                    idx = i
                    break
            if idx == 0:
                sd_bytes = tail
                msg = ""
            else:
                sd_bytes = tail[:idx]
                msg = tail[idx+1:].decode(errors="replace")
            sd = sd_bytes.decode(errors="replace")
        else:
            # malformed; treat all as msg
            sd = ""
            msg = tail.decode(errors="replace")
        d = {
            "ts": ts.decode(errors="replace"),
            "host": host.decode(errors="replace"),
            "app": app.decode(errors="replace"),
            "procid": procid.decode(errors="replace"),
            "msgid": msgid.decode(errors="replace"),
            "sd": sd,
            "msg": msg,
        }
        return d
    except Exception:
        return None

def parse_syslog(line: bytes):
    p = parse_pri(line)
    if not p:
        return None
    fac, sev, rest = p
    if detect_5424(rest):
        body = parse_5424(rest)
        fmt = "5424"
    else:
        body = parse_3164(rest)
        fmt = "3164"
    if not body:
        body = {"ts": "", "host": "", "app": "", "msg": rest.decode(errors="replace")}
    return {
        "facility": fac,
        "facility_name": FACILITY_NAMES[fac] if 0 <= fac < len(FACILITY_NAMES) else str(fac),
        "severity": sev,
        "severity_name": SEVERITY_NAMES[sev] if 0 <= sev < len(SEVERITY_NAMES) else str(sev),
        "format": fmt,
        **body,
        "raw": line
    }

# ---------- Networking servers ----------

class UDPServerThread(threading.Thread):
    def __init__(self, host: str, port: int, outq: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.outq = outq
        self.stop_event = stop_event
        self.sock = None

    def run(self):
        if self.port <= 0:
            return
        try:
            bound = False
            last_err = None
            for af, socktype, proto, canon, sa in socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE):
                try:
                    s = socket.socket(af, socktype, proto)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    # Attempt to allow dual-stack where supported (best-effort)
                    if af == socket.AF_INET6:
                        try:
                            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                        except Exception:
                            pass
                    s.bind(sa)
                    self.sock = s
                    bound = True
                    break
                except Exception as e2:
                    last_err = e2
                    try:
                        s.close()
                    except Exception:
                        pass
                    continue
            if not bound:
                raise last_err or OSError("getaddrinfo returned no usable addresses")
        except Exception as e:
            self.outq.put({"type": "event", "msg": f"[UDP] Failed to bind {self.host}:{self.port}: {e}"})
            return
        bound_addr = self.sock.getsockname()
        addr_str = f"[{bound_addr[0]}]:{bound_addr[1]}" if ':' in bound_addr[0] else f"{bound_addr[0]}:{bound_addr[1]}"
        self.outq.put({"type": "event", "msg": f"[UDP] Listening on {addr_str}"})
        self.sock.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            ts = datetime.now().isoformat(timespec="seconds")
            parsed = parse_syslog(data)
            if parsed is None:
                parsed = {"ts": ts, "host": addr[0], "app": "", "msg": data.decode(errors="replace"),
                          "facility": -1, "severity": 6, "severity_name": "INFO", "facility_name": "unknown",
                          "format": "unknown", "raw": data}
            parsed["src"] = f"{addr[0]}:{addr[1]}"
            self.outq.put({"type": "log", **parsed})
        try:
            self.sock.close()
        except Exception:
            pass

class ThreadedTCPServer(threading.Thread):
    def __init__(self, host: str, port: int, outq: queue.Queue, stop_event: threading.Event, tls_ctx: ssl.SSLContext = None):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.outq = outq
        self.stop_event = stop_event
        self.tls_ctx = tls_ctx
        self.sock = None

    def run(self):
        if self.port <= 0:
            return
        try:
            bound = False
            last_err = None
            for af, socktype, proto, canon, sa in socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
                try:
                    s = socket.socket(af, socktype, proto)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if af == socket.AF_INET6:
                        try:
                            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                        except Exception:
                            pass
                    s.bind(sa)
                    s.listen(100)
                    s.settimeout(0.5)
                    self.sock = s
                    bound = True
                    break
                except Exception as e2:
                    last_err = e2
                    try:
                        s.close()
                    except Exception:
                        pass
                    continue
            if not bound:
                raise last_err or OSError("getaddrinfo returned no usable addresses")
        except Exception as e:
            self.outq.put({"type": "event", "msg": f"[TCP] Failed to bind {self.host}:{self.port}: {e}"})
            return
        bound_addr = self.sock.getsockname()
        addr_str = f"[{bound_addr[0]}]:{bound_addr[1]}" if ':' in bound_addr[0] else f"{bound_addr[0]}:{bound_addr[1]}"
        self.outq.put({"type": "event", "msg": f"[TCP{'/TLS' if self.tls_ctx else ''}] Listening on {addr_str}"})
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
            t.start()
        try:
            self.sock.close()
        except Exception:
            pass

    def handle_client(self, conn: socket.socket, addr):
        peer = f"{addr[0]}:{addr[1]}"
        try:
            if self.tls_ctx:
                conn = self.tls_ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(1.0)
            buf = b""
            while not self.stop_event.is_set():
                # Attempt to read some data
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Parse frames from buf
                    while True:
                        if not buf:
                            break
                        # Try octet-counted framing: <len> <msg>
                        i = 0
                        while i < len(buf) and 48 <= buf[i] <= 57:  # digits
                            i += 1
                        if i > 0 and i < len(buf) and buf[i:i+1] == b" ":
                            try:
                                msg_len = int(buf[:i])
                                if len(buf) >= i + 1 + msg_len:
                                    msg = buf[i+1:i+1+msg_len]
                                    buf = buf[i+1+msg_len:]
                                    self._emit_tcp(msg, peer)
                                    continue
                            except ValueError:
                                pass  # fall back to LF
                        # LF-delimited (also accept CRLF)
                        nl = buf.find(b"\n")
                        if nl != -1:
                            line = buf[:nl]
                            # strip optional CR
                            if line.endswith(b"\r"):
                                line = line[:-1]
                            buf = buf[nl+1:]
                            if line:
                                self._emit_tcp(line, peer)
                            continue
                        # Need more data
                        break
                except socket.timeout:
                    continue
        except ssl.SSLError as e:
            self.outq.put({"type": "event", "msg": f"[TCP/TLS] SSL error from {peer}: {e}"})
        except Exception as e:
            self.outq.put({"type": "event", "msg": f"[TCP] Error with {peer}: {e}"})
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _emit_tcp(self, data: bytes, peer: str):
        ts = datetime.now().isoformat(timespec="seconds")
        parsed = parse_syslog(data)
        if parsed is None:
            parsed = {"ts": ts, "host": "", "app": "", "msg": data.decode(errors="replace"),
                      "facility": -1, "severity": 6, "severity_name": "INFO", "facility_name": "unknown",
                      "format": "unknown", "raw": data}
        parsed["src"] = peer
        self.outq.put({"type": "log", **parsed})

# ---------- TUI ----------



class TUI:
    def __init__(self, stdscr, outq: queue.Queue, stop_event: threading.Event, min_sev: int):
        self.stdscr = stdscr
        self.outq = outq
        self.stop_event = stop_event
        self.paused = False
        self.min_sev = min_sev  # display severities <= min_sev (lower is more severe)
        # store all lines with metadata to support dynamic filters
        # item = dict(sev:int, text:str, host:str, app:str)
        self.lines = []
        self.max_lines = 20000
        self.total = 0
        self.count_by_sev = [0]*8
        self.status_msgs = []
        self.help_visible = False
        # scrollback
        self.scroll_offset = 0  # 0 == follow tail, >0 == lines from bottom in filtered view
        # filters
        self.host_filter = ""   # case-insensitive substring (empty = no filter)
        self.app_filter  = ""   # case-insensitive substring
        # search
        self.search_query = ""
        self.search_matches = []   # list of filtered indexes (0..len(filtered)-1)
        self.search_pos = -1       # position within search_matches
        # filtered cache
        self.filtered_idx = []     # indexes into self.lines that pass filters+min_sev
        self.dirty = True          # set when lines/filters/min_sev/search change

    def run(self):
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        curses.start_color()
        curses.use_default_colors()
        self._init_colors()
        last_draw = 0
        while not self.stop_event.is_set():
            # consume queue
            try:
                for _ in range(500):
                    item = self.outq.get_nowait()
                    if item["type"] == "log":
                        self._on_log(item)
                    elif item["type"] == "event":
                        self._on_event(item["msg"])
                        self.dirty = True
            except queue.Empty:
                pass
            # handle input
            self._handle_keys()
            # redraw at ~30 fps
            now = time.time()
            if now - last_draw > (1/30):
                self._draw()
                last_draw = now
            time.sleep(0.01)

    def _init_colors(self):
        pairs = [
            (1, curses.COLOR_RED),      # EMERG
            (2, curses.COLOR_MAGENTA),  # ALERT
            (3, curses.COLOR_MAGENTA),  # CRIT
            (4, curses.COLOR_RED),      # ERR
            (5, curses.COLOR_YELLOW),   # WARN
            (6, curses.COLOR_CYAN),     # NOTICE
            (7, -1),                    # INFO
            (8, curses.COLOR_BLUE),     # DEBUG
        ]
        for idx, color in pairs:
            try:
                curses.init_pair(idx, color, -1)
            except Exception:
                pass

    def _on_log(self, rec):
        # Always record, filtering is applied in view so changing filters later works
        self.total += 1
        sev = rec.get("severity", 6)
        host = rec.get("host", "") or ""
        app = rec.get("app", "") or ""
        msg = rec.get("msg", "") or ""
        ts  = rec.get("ts", "") or ""
        sev_name = rec.get("severity_name", "INFO")
        if 0 <= sev <= 7:
            self.count_by_sev[sev] += 1
        text = f"{ts} {sev_name:<6} {host} {app} — {msg}"
        self.lines.append({"sev": sev, "text": text, "host": host, "app": app})
        if len(self.lines) > self.max_lines:
            # drop from the start
            drop = len(self.lines) - self.max_lines
            self.lines = self.lines[drop:]
            # adjust filtered/search indices later by rebuild
        self.dirty = True

    def _on_event(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.status_msgs.append(f"{ts} {text}")
        if len(self.status_msgs) > 5:
            self.status_msgs = self.status_msgs[-5:]

    def _prompt(self, prompt_text: str, initial: str = ""):
        # blocking line editor at bottom; returns string or None if cancelled
        h, w = self.stdscr.getmaxyx()
        curses.curs_set(1)
        self.stdscr.nodelay(False)
        buf = list(initial)
        pos = len(buf)
        while True:
            line = f"{prompt_text}{''.join(buf)}"
            # clear prompt row
            try:
                self.stdscr.addnstr(h-1, 0, " " * w, w)
                self.stdscr.addnstr(h-1, 0, line[:w], w, curses.A_REVERSE)
                self.stdscr.move(h-1, min(len(prompt_text)+pos, w-1))
                self.stdscr.refresh()
            except Exception:
                pass
            ch = self.stdscr.getch()
            if ch in (10, 13):  # Enter
                s = "".join(buf).strip()
                curses.curs_set(0); self.stdscr.nodelay(True)
                return s
            if ch in (27, ):    # ESC
                curses.curs_set(0); self.stdscr.nodelay(True)
                return None
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if pos > 0:
                    pos -= 1
                    buf.pop(pos)
                continue
            if ch in (curses.KEY_LEFT, ):
                if pos > 0: pos -= 1
                continue
            if ch in (curses.KEY_RIGHT, ):
                if pos < len(buf): pos += 1
                continue
            if ch == -1:
                continue
            # printable
            try:
                c = chr(ch)
            except Exception:
                c = ""
            if c and curses.ascii.isprint(ch):
                buf.insert(pos, c)
                pos += 1

    def _handle_keys(self):
        try:
            ch = self.stdscr.getch()
        except Exception:
            ch = -1
        if ch == -1:
            return
        # quit
        if ch in (ord('q'), ord('Q')):
            self.stop_event.set(); return
        # pause
        if ch in (ord('p'), ord('P')):
            self.paused = not self.paused
            self._on_event("Paused" if self.paused else "Resumed"); return
        # clear
        if ch in (ord('c'), ord('C')):
            self.lines.clear()
            self.filtered_idx.clear()
            self.search_matches.clear()
            self.scroll_offset = 0
            self.search_pos = -1
            self.dirty = True
            self._on_event("Cleared"); return
        # severity filter
        if ch in (ord('['), ):
            if self.min_sev > 0:
                self.min_sev -= 1; self.dirty = True
                self._on_event(f"Min severity: {SEVERITY_NAMES[self.min_sev]} ({self.min_sev})")
            return
        if ch in (ord(']'), ):
            if self.min_sev < 7:
                self.min_sev += 1; self.dirty = True
                self._on_event(f"Min severity: {SEVERITY_NAMES[self.min_sev]} ({self.min_sev})")
            return
        # help
        if ch in (ord('h'), ord('?')):
            self.help_visible = not self.help_visible; return
        # scrolling
        if ch in (curses.KEY_UP, ord('k')): self._scroll_lines(1); return
        if ch in (curses.KEY_DOWN, ord('j')): self._scroll_lines(-1); return
        if ch == curses.KEY_PPAGE: self._scroll_page(1); return
        if ch == curses.KEY_NPAGE: self._scroll_page(-1); return
        if ch in (curses.KEY_HOME, ord('g')): self._scroll_to_top(); return
        if ch in (curses.KEY_END, ord('G')): self._scroll_to_bottom(); return
        # search
        if ch == ord('/'):
            s = self._prompt("Search: ", self.search_query)
            if s is not None:
                self.search_query = s
                self.search_pos = -1
                self.dirty = True
            return
        if ch in (ord('n'), ord('N')):
            if not self.search_matches:
                self._on_event("No matches"); return
            step = 1 if ch == ord('n') else -1
            self.search_pos = (0 if self.search_pos == -1 else self.search_pos + step) % len(self.search_matches)
            idx = self.search_matches[self.search_pos]
            self._scroll_to_filtered_index(idx)
            return
        # filters
        if ch in (ord('H'), ):
            s = self._prompt("Host filter (empty=clear): ", self.host_filter)
            if s is not None:
                self.host_filter = s
                self.scroll_offset = 0
                self.dirty = True
            return
        if ch in (ord('A'), ):
            s = self._prompt("App filter (empty=clear): ", self.app_filter)
            if s is not None:
                self.app_filter = s
                self.scroll_offset = 0
                self.dirty = True
            return
        # save
        if ch in (ord('s'), ):
            default = datetime.now().strftime("syslog-view-%Y%m%d-%H%M%S.txt")
            fname = self._prompt(f"Save visible to file [{default}]: ", "")
            if fname is None:
                return
            if not fname.strip():
                fname = default
            try:
                subset = self._current_visible_subset()
                with open(fname, "w", encoding="utf-8") as f:
                    for _, text in subset:
                        f.write(text + "\n")
                self._on_event(f"Saved {len(subset)} lines to {fname}")
            except Exception as e:
                self._on_event(f"Save failed: {e}")
            return

    def _scroll_lines(self, n):
        max_off = max(0, len(self._filtered()) - 1)
        self.scroll_offset = min(max(0, self.scroll_offset + n), max_off)

    def _scroll_page(self, n_pages):
        h, w = self.stdscr.getmaxyx()
        view_top = 6 if self.help_visible else 4  # account for extra header line
        max_rows = max(0, h - view_top - 1)
        delta = n_pages * max(1, max_rows - 1)
        self._scroll_lines(delta)

    def _scroll_to_top(self):
        self.scroll_offset = max(0, len(self._filtered()) - 1)

    def _scroll_to_bottom(self):
        self.scroll_offset = 0

    def _scroll_to_filtered_index(self, i):
        # set scroll_offset so that filtered index i is visible
        filtered = self._filtered()
        F = len(filtered)
        if F == 0:
            self.scroll_offset = 0; return
        h, w = self.stdscr.getmaxyx()
        view_top = 6 if self.help_visible else 4
        R = max(0, h - view_top - 1)
        self.scroll_offset = max(0, F - R - i)

    def _filtered(self):
        if not self.dirty:
            return self.filtered_idx
        # rebuild filtered_idx
        self.filtered_idx = []
        host_q = self.host_filter.strip().lower()
        app_q  = self.app_filter.strip().lower()
        for i, it in enumerate(self.lines):
            if it["sev"] > self.min_sev:
                continue
            if host_q and host_q not in (it["host"] or "").lower():
                continue
            if app_q and app_q not in (it["app"] or "").lower():
                continue
            self.filtered_idx.append(i)
        # rebuild search matches
        self.search_matches = []
        if self.search_query.strip():
            q = self.search_query.lower()
            for pos, idx in enumerate(self.filtered_idx):
                if q in self.lines[idx]["text"].lower():
                    self.search_matches.append(pos)
        # clamp scroll offset and search_pos
        max_off = max(0, len(self.filtered_idx) - 1)
        self.scroll_offset = min(self.scroll_offset, max_off)
        if self.search_pos >= len(self.search_matches):
            self.search_pos = -1
        self.dirty = False
        return self.filtered_idx

    def _current_visible_subset(self):
        filtered = self._filtered()
        h, w = self.stdscr.getmaxyx()
        view_top = 6 if self.help_visible else 4
        max_rows = max(0, h - view_top - 1)
        total = len(filtered)
        if total <= max_rows:
            start = 0
        else:
            start = max(0, total - max_rows - self.scroll_offset)
        end = min(total, start + max_rows)
        # return list of (sev, text)
        out = []
        for idx in filtered[start:end]:
            it = self.lines[idx]
            out.append((it["sev"], it["text"]))
        return out

    def _draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        filtered = self._filtered()
        # Header 1
        sev_counts = " ".join(f"{SEVERITY_NAMES[i]}:{self.count_by_sev[i]}" for i in range(8))
        follow = "TAIL" if self.scroll_offset == 0 else "SCROLL"
        header = f" syslog-tui — total:{self.total}  min-sev:<={SEVERITY_NAMES[self.min_sev]}({self.min_sev})  view:{follow}  {sev_counts} "
        try:
            self.stdscr.addnstr(0, 0, header.ljust(w), w, curses.A_REVERSE)
        except Exception:
            pass
        # Header 2: filters/search
        filt = f" host='{self.host_filter or '*'}' app='{self.app_filter or '*'}'  search='{self.search_query or ''}'  matches:{len(self.search_matches)} "
        try:
            self.stdscr.addnstr(1, 0, filt.ljust(w), w, curses.A_DIM)
        except Exception:
            pass
        # Status
        for i, s in enumerate(self.status_msgs[-2:]):
            try:
                self.stdscr.addnstr(2+i, 0, s.ljust(w), w)
            except Exception:
                pass
        # Help overlay
        if self.help_visible:
            help_lines = [
                "Keys: q quit  p pause  c clear  [ / ] raise/lower min severity  h/? help",
                "Scroll: ↑/k, ↓/j, PgUp/PgDn, Home(g)/End(G)",
                "Search: / to set query, n next, N prev  |  Filters: H host, A app",
                "Save: s (visible window)",
            ]
            for i, s in enumerate(help_lines):
                try:
                    self.stdscr.addnstr(4+i, 0, s.ljust(w), w)
                except Exception:
                    pass
        # Log window
        view_top = 6 if self.help_visible else 4
        max_rows = max(0, h - view_top - 1)
        total = len(filtered)
        if total <= max_rows:
            start = 0
        else:
            start = max(0, total - max_rows - self.scroll_offset)
        end = min(total, start + max_rows)
        # Render subset
        row = view_top
        # if a current match is visible, compute its absolute filtered index
        cur_match_abs = self.search_matches[self.search_pos] if (self.search_matches and self.search_pos != -1) else None
        for i in range(start, end):
            idx = filtered[i]
            it = self.lines[idx]
            sev = it["sev"]
            text = it["text"]
            attr = curses.color_pair(min(max(sev+1,1),8)) | (curses.A_BOLD if sev <= 2 else 0)
            # highlight current match line
            if cur_match_abs is not None and i == cur_match_abs:
                attr |= curses.A_REVERSE
            try:
                self.stdscr.addnstr(row, 0, text.ljust(w), w, attr)
            except Exception:
                pass
            row += 1
        # Footer
        footer = " q quit │ p pause │ c clear │ [ / ] severity │ ↑/↓ PgUp/PgDn Home/End │ / n N search │ H host A app │ s save "
        try:
            self.stdscr.addnstr(h-1, 0, footer.ljust(w), w, curses.A_REVERSE)
        except Exception:
            pass
        self.stdscr.refresh()
# ---------- TLS context (server-side) ----------

def make_server_tls_context(certfile: str, keyfile: str, cafile: str = None, require_client_cert: bool = False, insecure: bool = False):
    if not certfile or not keyfile:
        raise ValueError("TLS requires --certfile and --keyfile")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    if cafile:
        ctx.load_verify_locations(cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = ssl.CERT_NONE
    # 'insecure' here means we won't verify client cert at all
    if insecure:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(description="TUI syslog collector (UDP/TCP/TLS) with live, colorised output.")
    ap.add_argument("--udp-host", default="0.0.0.0", help="UDP bind address (IPv4/IPv6). Use 0.0.0.0 or :: (default: 0.0.0.0)")
    ap.add_argument("--udp-port", type=int, default=514, help="UDP port to listen on (0=disabled)")
    ap.add_argument("--tcp-host", default="0.0.0.0", help="TCP bind address (IPv4/IPv6). Use 0.0.0.0 or :: (default: 0.0.0.0)")
    ap.add_argument("--tcp-port", type=int, default=10514, help="TCP port to listen on (0=disabled)")
    ap.add_argument("--tls", action="store_true", help="Enable TLS on TCP (server-side). Requires --certfile and --keyfile.")
    ap.add_argument("--certfile", help="Server certificate (PEM) for TLS")
    ap.add_argument("--keyfile", help="Server key (PEM) for TLS")
    ap.add_argument("--cafile", help="Client CA to verify clients (optional)")
    ap.add_argument("--require-client-cert", action="store_true", help="Require and verify client certificates (mTLS)")
    ap.add_argument("--insecure", action="store_true", help="Do not verify client certificate (TLS)")
    ap.add_argument("--min-severity", type=int, default=7, help="Initial minimum severity to display (0=EMERG .. 7=DEBUG). Show severities <= value.")
    args = ap.parse_args()

    # TLS sanity
    tls_ctx = None
    if args.tls:
        try:
            tls_ctx = make_server_tls_context(args.certfile, args.keyfile, cafile=args.cafile,
                                              require_client_cert=args.require_client_cert, insecure=args.insecure)
        except Exception as e:
            print(f"TLS setup failed: {e}", file=sys.stderr)
            sys.exit(2)

    # Queue and stop event
    outq = queue.Queue(maxsize=10000)
    stop_event = threading.Event()

    # Start servers
    threads = []
    if args.udp_port > 0:
        t = UDPServerThread(args.udp_host, args.udp_port, outq, stop_event)
        t.start()
        threads.append(t)
    if args.tcp_port > 0:
        t = ThreadedTCPServer(args.tcp_host, args.tcp_port, outq, stop_event, tls_ctx=tls_ctx)
        t.start()
        threads.append(t)

    if not threads:
        print("No listeners enabled. Set --udp-port and/or --tcp-port to non-zero.", file=sys.stderr)
        sys.exit(1)

    # Launch TUI
    try:
        curses.wrapper(lambda stdscr: TUI(stdscr, outq, stop_event, min_sev=args.min_severity).run())
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(0.2)

if __name__ == "__main__":
    main()
