# syslog-tui — Terminal UI Syslog Collector

`syslog-tui.py` is a dependency‑free, curses‑based syslog collector that shows **live, colourised logs** in your terminal.  
It supports **UDP**, **TCP**, and **TLS**; auto‑detects **RFC6587 framing** (octet‑counted or LF‑delimited); and parses **RFC3164** and **RFC5424** messages.

> **Note:** In most environments **sudo is required when setting a bind address** (and always for privileged ports like 514/6514).

---

## Features

- **Transports:** UDP, TCP, optional **TLS** (server-side) on TCP
- **Framing:** Auto-detects **RFC6587** octet-counted vs **LF**-delimited on TCP
- **Formats:** Parses **RFC3164** (BSD) and **RFC5424**
- **Colour by severity:** EMERG/ALERT/CRIT/ERR/WARN/NOTICE/INFO/DEBUG
- **IPv4/IPv6 binding:** Bind to any interface or a specific address (e.g., `0.0.0.0`, `::`, `10.0.2.163`)
- **Configurable ports:** Independent UDP/TCP ports; set to `0` to disable either listener
- **Scrollback:** Line and page scrolling, jump to top/bottom
- **Search:** `/` to search; `n`/`N` to navigate matches
- **Filters:** Filter by **host** (`H`) and **app** (`A`) substrings; adjust **severity threshold** `[` / `]`
- **Save view:** `s` saves the **visible window** to a file
- **Live stats:** Totals and per‑severity counters
- **No third‑party libraries:** Pure Python standard library (3.8+)

---

## Requirements

- Python **3.8+**
- A terminal that supports **curses** (Linux/macOS; on Windows use WSL or a terminal that supports ANSI/curses)
- Permissions:  
  - **sudo is required when setting a bind address** and/or listening on privileged ports (`<1024`, e.g., **514**, **6514**).

---

## Install

Download the script and make it executable:
```bash
curl -L -o syslog-tui.py "<your repo or file URL>"
chmod +x syslog-tui.py
```

Run help:
```bash
python3 syslog-tui.py -h
```

---

## Quick start

Listen on **UDP 5514** only:
```bash
sudo python3 syslog-tui.py --udp-host 0.0.0.0 --udp-port 5514 --tcp-port 0
```

Listen on **TCP 10514** (octet or LF framing auto-detected):
```bash
sudo python3 syslog-tui.py --udp-port 0 --tcp-host 0.0.0.0 --tcp-port 10514
```

Enable **TLS** on **6514** (server cert/key required):
```bash
sudo python3 syslog-tui.py --udp-port 0 --tcp-port 6514 --tcp-host ::   --tls --certfile server.crt --keyfile server.key
```

Bind to a **specific interface/IP**:
```bash
sudo python3 syslog-tui.py --udp-host 10.0.2.163 --udp-port 514 --tcp-port 0
```

Send test logs with `syslog-pro.py`:
```bash
# RFC5424 over TCP (octet-framed)
python3 syslog-pro.py 127.0.0.1 --transport tcp -p 10514 --format 5424 -n 10 -m "hello {seq}"

# RFC3164 over UDP
python3 syslog-pro.py 127.0.0.1 -p 5514 --format 3164 -n 10 -m "udp test {seq}"
```

---

## CLI synopsis

```text
usage: syslog-tui.py [--udp-host UDP_HOST] [--udp-port UDP_PORT]
                     [--tcp-host TCP_HOST] [--tcp-port TCP_PORT]
                     [--tls] [--certfile CERTFILE] [--keyfile KEYFILE]
                     [--cafile CAFILE] [--require-client-cert] [--insecure]
                     [--min-severity MIN_SEVERITY]

TUI syslog collector (UDP/TCP/TLS) with live, colorised output.
```

**Common flags**
- `--udp-host` (default `0.0.0.0`) — **bind address** for UDP (IPv4/IPv6 supported; use `::` for IPv6)
- `--udp-port` (default `514`) — UDP port (set `0` to disable UDP)
- `--tcp-host` (default `0.0.0.0`) — **bind address** for TCP
- `--tcp-port` (default `10514`) — TCP port (set `0` to disable TCP)
- `--tls` — enable TLS on TCP (server-side). Requires `--certfile` and `--keyfile`
- `--certfile`, `--keyfile` — PEM files for TLS
- `--cafile` — CA file to verify client certs (optional)
- `--require-client-cert` — require mTLS from clients
- `--insecure` — don’t verify client certificates (debug only)
- `--min-severity` — initial severity threshold (0=EMERG .. 7=DEBUG; default `7`)

> **Binding & privileges:** Using a bind address (e.g., `--udp-host 10.0.2.163`) typically requires **sudo**, and any port below 1024 always requires elevated privileges or the `CAP_NET_BIND_SERVICE` capability.

---

## Key bindings

- **q** — quit
- **p** — pause/resume display
- **c** — clear buffer
- **[** / **]** — raise/lower **minimum severity** (show only more severe / include less severe)
- **h** or **?** — toggle help
- **Scrolling:** ↑/k, ↓/j, **PageUp/PageDown**, **Home(g)/End(G)**
- **Search:** `/` set query, **n** next match, **N** previous match
- **Filters:** **H** set host filter, **A** set app filter (substring; empty to clear)
- **Save:** **s** save the **visible window** to a file

**Status line**
- Shows **TAIL** when following the end of the stream, **SCROLL** when viewing history.

---

## Formats & framing

- Parses **RFC3164** and **RFC5424** automatically (based on version field after PRI).
- TCP framing auto‑detected:
  - **Octet-counted:** `<length> <payload>` per **RFC6587**
  - **LF-delimited:** payloads separated by `\n` (CRLF tolerated)

---

## TLS notes

- Provide a server certificate and key (`--certfile`, `--keyfile`) to accept TLS connections (6514 typical).
- To require **mTLS**, add `--cafile` and `--require-client-cert`.
- Use `--insecure` only for quick connectivity tests (no client verification).

---

## Filtering & search

- **Severity threshold**: `[` shows only more severe; `]` includes less severe (0..7).
- **Host/App filters**: set with **H**/**A**; substring, case‑insensitive.
- **Search**: `/` to enter query; **n**/**N** to jump between matches. Current match is highlighted.

---

## Saving output

Press **s** to save the **currently visible** lines to a timestamped file (you can override the suggested name).

---

## Troubleshooting

- **Permission denied / address in use**: Use **sudo**, confirm the port isn’t already bound, and check firewalls/SELinux.
- **No logs shown**: Verify correct protocol/port/framing/format on the sender; try UDP vs TCP.
- **TLS handshake fails**: Confirm cert/key paths, client trust, and SNI (if used by sender).
- **IPv6/dual‑stack**: Use `--tcp-host ::` or `--udp-host ::`. Dual‑stack is attempted by disabling `IPV6_V6ONLY` where supported.
- **High volume**: Increase terminal size, use TCP, and consider piping to a file (future feature: disk persistence).

---

## Security considerations

- Running as root (or with `sudo`) exposes risks. Prefer binding to non‑privileged ports for testing where possible.
- Limit network access to the collector host when accepting logs from untrusted networks.

---

## License

MIT License
