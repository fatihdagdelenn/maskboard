# ClipVeil

ClipVeil masks the sensitive parts of logs and configs before you paste them into
ChatGPT, Claude or any other AI assistant. It replaces IPs, hostnames, domains, users,
containers, network interfaces, config values and secrets with typed tokens. When the
AI answers, ClipVeil turns the tokens back into your real values.

Everything runs on your machine. ClipVeil makes no network connections and no data
leaves your computer.

![ClipVeil](screenshot.png)

```
Real:    alice@web01:~/projects/shop$ docker logs shop-web-1
         DATABASE_URL=postgresql://appuser:S3cret.1@db01.example-corp.com:5432/shopdb
         inet 10.10.10.20/24 brd 10.10.10.255 scope global ens192

Masked:  USER_1@HOST_1:~/projects/PROJECT_1$ docker logs PROJECT_1-web-1
         DATABASE_URL=postgresql://USER_2:PASSWORD_1@DOMAIN_1:5432/DB_1
         inet IP_PRIV_1/24 brd IP_PRIV_2 scope global ens192
```

The same real value always gets the same token. The AI can see what was hidden and
how values relate, so its answer uses the same tokens. When you copy the answer,
the tokens are replaced with your real values again.

Two editions share one masking engine and give identical output:

- **Desktop app** (`clipveil.py`): watches the clipboard and masks or restores
  automatically. It also has global hotkeys and a tray icon. Windows, Linux and macOS.
- **Web page** (`clipveil.html`): one self-contained file you can open in any browser,
  with no installation.

Both editions have an English and a Turkish interface. They pick one from your system
or browser language, and you can switch between them at any time.

## Tokens

| Token | What it hides | Example |
|---|---|---|
| `IP_PRIV_n`, `IP_PUB_n` | Private (RFC 1918, CGNAT, link-local) and public IPv4; the `/prefix` is kept | `10.10.10.0/24` → `IP_PRIV_1/24` |
| `IPV6_PRIV_n`, `IPV6_PUB_n` | IPv6 addresses (ULA and link-local count as private) | `fe80::250:56ff:fea1:b2c3/64` → `IPV6_PRIV_1/64` |
| `HOST_n` | Hostnames | `web01` → `HOST_1` |
| `DOMAIN_n` | Domain names; a full name is one token | `test.example-corp.com` → `DOMAIN_1` |
| `URL_n` | `http://` and `https://` addresses, including the path | `https://portal.example-corp.com/login?x=1` → `URL_1` |
| `USER_n` | User names | `alice@web01:~$` → `USER_1@HOST_1:~$` |
| `PROJECT_n`, `CONTAINER_n` | Project and container names | `shop-web-1` → `PROJECT_1-web-1`, `nostalgic_hopper` → `CONTAINER_1` |
| `IFACE_n` | Non-standard network interfaces | `br-3f2a1b4c5d6e` → `IFACE_1` |
| `MAIL_n` | Email addresses | `ops@example-corp.com` → `MAIL_1` |
| `MAC_n` | MAC addresses | `00:1B:44:11:3A:B7` → `MAC_1` |
| `DS_n`, `JNDI_n`, `DB_n`, `SCHEMA_n`, `CONFIG_n` | Datasource, JNDI, database, schema and other config values | `datasource billing` → `datasource DS_1` |
| `PASSWORD_n`, `TOKEN_n`, `SECRET_n` | Passwords, tokens, private keys | `password: Hunter2!` → `password: PASSWORD_1` |
| `DATE_n` | Dates (optional) | `2026-10-01` → `DATE_1` |
| `CUSTOM_n` | Terms you type into the custom terms box | `ACME Ltd.` → `CUSTOM_1` |

Tokens are deliberately not wrapped in `<…>`. Chat interfaces render answers as HTML, so
`<url1>` can disappear on screen, and it looks like a tag inside XML configs. A plain
`IP_PRIV_1` survives Markdown, XML, JSON and shells unchanged. A token is never matched
inside an upper-case identifier, so environment variables such as `DB_HOST_1` and
`DB_PASSWORD_1` are left alone when an answer is restored.

## Files

| File | Purpose |
|---|---|
| `clipveil.py` | Desktop app: clipboard capture, hotkeys, tray icon |
| `clipveil.html` | Web page: no installation, open it in a browser |
| `requirements.txt` | Python packages for the desktop app |
| `build_windows.bat` | Builds a single `ClipVeil.exe` on Windows |
| `build_linux.sh` | Builds a single `clipveil` executable on Linux |
| `clipveil.ico`, `clipveil.png` | App icon |
| `tests/` | Regression tests: samples, expected masked output, web parity test |

## Quick start

**Windows / macOS**
```bash
pip install -r requirements.txt
python clipveil.py
```

**Linux** (recent Ubuntu/Debian refuse `pip install` into the system Python, so use a virtual environment)
```bash
sudo apt install python3-tk python3-venv xclip     # Fedora: sudo dnf install python3-tkinter xclip
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python clipveil.py
```

**Web:** open `clipveil.html` in a browser.

To use the desktop app without installing Python, see [Building](#building).

## Using the desktop app

### Automatic: copy and paste

When the clipboard is available, **Auto-watch** turns on at startup. The status card
shows whether protection is on and what happened last.

1. Copy a log (`Ctrl+C`). The clipboard now holds the masked version.
2. Paste it into the AI (`Ctrl+V`).
3. Copy the AI's answer (`Ctrl+C`). The tokens turn back into real values.
4. Paste it into your editor or terminal (`Ctrl+V`).

ClipVeil decides from the content whether a copy is a log or an AI answer. If known
tokens dominate, it restores the copy. If the copy contains new sensitive values, it
masks them. When in doubt it masks, so real data never reaches the AI by mistake.
Copying the same masked text again also triggers a restore.

The **Mode** switch changes this behaviour:

- `Smart` (default): logs are masked and AI answers are restored.
- `Mask only`: every copy is masked, and you restore manually.

### Manual: tabs

- **Mask:** paste a log, choose the categories, press *Mask* (or `Ctrl+Enter`), then *Copy*.
- **Restore:** paste the AI's answer, press *Restore* (or `Ctrl+Enter`), then *Copy*.
- **Ledger:** the real ↔ token table, newest first, with search, export, import and
  reset. Secrets appear as `••••••••`.

Categories are grouped as **Network** (IPv4, IPv6, DNS, URL, Host, MAC, Interface) and
**Identity & secrets** (User, Email, Container, Config, Secret, Date, Custom). All of them
except Date are on by default; turn off any that masks too much. Use the **custom terms**
box for words that are not detected automatically, such as a company name.

The **EN | TR** switch in the header changes the interface language immediately. The
choice is remembered.

### Hotkeys

| Hotkey | Action |
|---|---|
| `Ctrl+Alt+A` | Mask the clipboard |
| `Ctrl+Alt+R` | Restore the clipboard |
| `Ctrl+Alt+T` | Toggle auto-watch |
| `Ctrl+Enter` | Process the focused box (inside the window) |
| `Ctrl+Q` | Quit (inside the window) |

The `Ctrl+Alt` hotkeys work in every application and need the `pynput` package. Closing
the window does not quit the app: on Windows it goes to the tray, and on Linux it is
minimised, so watching continues.

## Using the web page

`clipveil.html` uses the same engine as the desktop app. It has no clipboard watching and
no hotkeys; you paste text and use the buttons (`Ctrl+Enter` masks or restores). The
ledger lives in the open tab by default. If you tick **Remember in this browser**, the
ledger is saved in the browser's local storage without secrets, and unticking the box
deletes the saved copy. If you paste a tokenized AI answer into the left box, the page
notices and offers to move it to the Restore box. Ledgers exported from the desktop app
can be imported, and the other way round.

## What gets masked, and what doesn't

**Masked:**

- IPv4/IPv6 addresses, including ones glued to text such as `node_192.168.22.22`.
- Domain names (a full name is one token) and `http(s)://` addresses.
- Email and MAC addresses.
- Hostnames such as `server01` and `db-prod-01`.
- Config values such as `datasource billing`, `jndi-name="java:/AppDS"` and `DB_NAME=appdb`.

**Context comes first.** The structures below say exactly what a value is, so they are
checked before the generic patterns, and names without digits are caught too:

| Context | Extracted |
|---|---|
| Shell prompts: `user@host:~/dir$`, `[user@host dir]$`, `PS C:\Users\…>` | user → `USER`, host → `HOST`, project directory → `PROJECT` |
| `ip a`, `ifconfig`, `ip route`, `dev …`, `master …` | non-standard interface → `IFACE` |
| `docker ps` table, `--name`, `container_name:`, `docker logs/exec/restart …`, `docker inspect` | container → `PROJECT_n-service-n` or `CONTAINER` |
| `com.docker.compose.project`, `COMPOSE_PROJECT_NAME`, `docker compose -p`, `PWD=`, JBoss `Deployed "x.war"`, nginx `upstream x_backend` | project → `PROJECT` |
| `/etc/hosts` lines, `HOSTNAME=`, the host column of journal/syslog, `ssh user@host` | host → `HOST` / `DOMAIN` |
| `*_USER`, `*_USERNAME`, `user=`, `--user`, `-u name` (mysql, psql, sudo, docker exec…), `/home/name`, `uid=1001(name)`, sshd and sudo logs | user → `USER` |
| `scheme://user:password@host:port/database` | each part separately: `USER`, `PASSWORD`, `HOST`/`DOMAIN`, `DB` |

**URLs.** `https://api.example-corp.com/v1/health` becomes `URL_1` as a whole, with
three exceptions:

- Local and public addresses such as `localhost`, `127.0.0.1` and `github.com` are left alone.
- In nginx, `proxy_pass http://shop_backend` stays as it is when it points at an `upstream`
  block in the same text, so the AI can see the link between the two.
- A URL that contains a password or token (`https://user:pass@…`, `?api_key=…`,
  `?token=…`) is never stored in the ledger as a whole, because the secret would then reach
  the disk. It is masked piece by piece instead: `https://USER_1:PASSWORD_1@DOMAIN_1/v1`.

**Learned names spread.** Users, projects and containers learned once keep their token in
later messages, even in a plain sentence without context. A project name also keeps its
token in image paths (`DOMAIN_1/PROJECT_1/web:2.4`), compose network names
(`PROJECT_1_default`) and nginx log file names. The same goes for domains and URLs: after
`billing.example-corp.com` has been masked, a bare `billing` elsewhere is hidden as
`HOST_n` too.

**Containers.** Every container name is masked. In compose names (`project-service-n`)
only the user-specific project part is hidden, so the service name and index stay visible
to the AI: `shop-web-1` → `PROJECT_1-web-1`. The one exception is a container named
exactly like its public image. For example, `open-webui` running from
`ghcr.io/open-webui/open-webui` stays visible, because the image column already shows the
name and it says nothing about you.

**Images.** Local images in `docker ps` and `docker images` output count as project names
and become `PROJECT_n`. Local here means no registry and not an official Docker Hub image,
such as `inventory-hub`. For compose-built `project-service` images only the project part is
hidden: `vm-inventory-app` → `PROJECT_2-app`. Official images such as `postgres:16-alpine`
and `redis:7`, and images from public registries such as `ghcr.io` and `quay.io`, are left
alone.

**System accounts** such as `root`, `admin`, `postgres`, `www-data`, `oracle` and `deploy`
are not masked: they are not sensitive and they help the AI. To hide them too, set
`MASK_SYSTEM_USERS = True` in `clipveil.py`.

**Secrets.** The following are masked:

- Any value whose key contains a password word in English, German, Spanish, French,
  Portuguese, Dutch, Polish, Swedish or Turkish (`password`, `Passwort`, `contraseña`,
  `mot_de_passe`, `senha`, `wachtwoord`, `hasło`, `lösenord`, `şifre`, …), or the words
  `secret`, `token` or `api_key`. This covers forms like `password=…`, `"password": "…"`,
  `<password>…</password>`, `spring.datasource.password=…`, `DB_PASSWORD=…` and `--password …`.
- Passwords inside connection URLs.
- `Authorization: Bearer …` headers.
- `*_SECRET`, `*_KEY`, `*_TOKEN` and `*_PASS` environment variables.
- `curl -u user:password`.
- JWTs and keys from AWS, GitHub, GitLab, Slack, Stripe, Google and Vault.
- The body of `-----BEGIN … PRIVATE KEY-----` blocks; the header lines stay visible.

As a fallback, random-looking strings of 20+ characters mixing upper case, lower case and
digits become `TOKEN_n`. When the same secret appears elsewhere without a key, it is hidden
there too.

Some values that look like secrets are left alone:

- Variable references such as `${DB_PASS}`.
- Empty values such as `password: null`.
- Metadata keys such as `PASSWORD_MIN_LENGTH`, `TOKEN_URL` and `DB_PASSWORD_FILE`.
- `PWD=`, which is the working directory.

**Dates** such as `2026-10-01`, `01.10.2026`, `30/09/2026`, `01/Oct/2026` and `Oct 1, 2026`
are always recognised, so they are never mistaken for IPs or hosts. They are not masked by
default because timelines matter when debugging; turn on the **Date** category to hide
them.

**Left alone** (the AI needs these to understand the log; they are not sensitive):

- Java packages and classes: `org.jboss.as.controller`, `AbstractPool.java`
- File names: `server.log`, `standalone.xml`
- Error codes: `WFLYCTL0013`, `ORA-00942`, `HHH000412`
- Log noise: `thread-12`, `pool-3`, `worker-7`, timestamps
- Versions and architectures: `java17`, `rhel8`, `jboss-eap-7.4.12`, `java-17-openjdk-amd64`, `TLSv1.2`, `x86_64`
- Command keywords: `inet`, `inet6`, `link/ether`, `qdisc`, `brd`, `scope`, `ssh2`, `overlay2`
- Standard interfaces: `lo`, `eth*`, `ens*`, `enp*`, `eno*`, `docker0`, `veth*`, `virbr*`, `wg*`, `bond*`
- Special addresses:
  - `127.0.0.0/8`, `0.0.0.0`, `::1`, `::` and multicast
  - netmasks such as `255.255.255.0` and well-known blocks such as `10.0.0.0/8`
  - `00:00:00:00:00:00` and `ff:ff:ff:ff:ff:ff`
  - `localhost`, `ip6-localhost`, `ip6-allnodes` and similar entries in `/etc/hosts`
- Public domains and registries: `docker.io`, `ghcr.io`, `quay.io`, `gcr.io`,
  `registry.k8s.io`, `github.com`, `redhat.com`, `docs.oracle.com`
- Container IDs, `sha256` digests and git commits (hex identifiers)

## Upgrading from Anonim Ajan

ClipVeil was previously called *Anonim Ajan*, and the upgrade is automatic:

- The desktop ledger moves from `~/.anonim_ajan.json` to `~/.clipveil.json` on first start.
- The web page moves a ledger saved in the browser to its new storage key.
- Tokens from older releases (`IP_5`, `HOST_10`, `KULLANICI_1`, `PROJE_2`, `PAROLA_1`,
  `AYAR_3`, `OZEL_1`, `TARIH_1`) still restore. They are replaced with the current tokens
  (`IP_PRIV_3`, `IFACE_1`, `USER_1`, `PROJECT_1`, …) the next time the value is masked.

The realistic fake values of the very first release (`relay66z.serdivan.systems`) also
still restore. If the app warns about them at startup, reset the ledger once.

## Tests

`tests/fixtures/` holds realistic samples, and `tests/expected/` holds the expected masked
version of each. The samples cover:

- `ip a`, `docker ps` and `docker images`
- `.env`, `/etc/hosts`, `env` and `docker inspect`
- an nginx config, `journalctl` output and a JBoss log
- shell prompts and connection strings

`tests/rules.json` lists the values that must never leak and the values that must stay
untouched.

```bash
python tests/test_masking.py            # run
python tests/test_masking.py --update   # rewrite the expected outputs
node tests/test_web_engine.js           # web page only
```

Each sample is checked to make sure that:

- the output matches the expected file exactly, also with Windows line endings (`\r\n`);
- no real value leaks;
- the values that must stay (`ens192`, `::1`, `ghcr.io`…) are untouched;
- restoring gives back the original text;
- masking the masked text changes nothing.

Further checks cover:

- consistent tokens across messages;
- upgrades from older ledgers;
- key formats;
- password words in several languages;
- token boundaries;
- URL and domain rules;
- the log / AI answer classification.

No GUI packages are needed, and `pytest tests/` works too.

The web page is tested against the same expected files: `tests/test_web_engine.js` extracts
the engine between `ENGINE START` and `ENGINE END` in `clipveil.html` and runs the same
checks. When Node is installed, `python tests/test_masking.py` runs it as well. If you
change a rule, change it in both engines; the web test fails if one is forgotten. If a test
fails after a change, read the diff first, and only use `--update` when you are sure the new
output is right.

## Building

PyInstaller does not cross-compile: build the Windows `.exe` on Windows and the Linux
binary on Linux.

**Windows:**

1. Put `build_windows.bat` next to `clipveil.py` and double-click it.
2. The result is `dist\ClipVeil.exe`, with the icon embedded. It runs on machines without
   Python.
3. If Explorer still shows an old icon, copy the exe to another folder; Windows refreshes
   its icon cache late.
4. To start it with Windows, put a shortcut in `Win+R → shell:startup`.

**Linux:**
```bash
chmod +x build_linux.sh && ./build_linux.sh          # other Python: PYTHON=python3.12 ./build_linux.sh
```
The script:

- checks the system packages and prints the install command if something is missing;
- installs the Python packages into `.venv` and leaves the system Python untouched;
- produces `dist/clipveil`, which runs without Python on Linux machines of the same
  architecture.

Build on a desktop session, not on a headless server: the hotkey modules look for a display
during the build.

**Add to the Linux menu and start at login** (after the build, in the same folder):
```bash
mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons ~/.config/autostart
cp dist/clipveil ~/.local/bin/
cp dist/clipveil.png ~/.local/share/icons/
cat > ~/.local/share/applications/clipveil.desktop <<EOF
[Desktop Entry]
Type=Application
Name=ClipVeil
Comment=Mask logs and configs before sending them to an AI
Exec=$HOME/.local/bin/clipveil
Icon=$HOME/.local/share/icons/clipveil.png
Terminal=false
Categories=Utility;
EOF
cp ~/.local/share/applications/clipveil.desktop ~/.config/autostart/
```
To stop it starting at login, delete `~/.config/autostart/clipveil.desktop`.

## Platform notes

- **Windows:** everything works.
- **Linux, X11 (Xorg session):** everything works, including detecting a repeated copy of
  the same text. The clipboard needs `xclip` or `xsel`.
- **Linux, Wayland (the default on recent Ubuntu/Fedora):**
  - The boxes work, and clipboard capture usually works; install `wl-clipboard` if it doesn't.
  - Global hotkeys and repeated-copy detection may not work.
  - For everything, choose "Ubuntu on Xorg" / "GNOME on Xorg" from the ⚙ menu on the
    login screen. Check your session type with `echo $XDG_SESSION_TYPE`.
- **Linux tray icon:** shown on KDE, XFCE, Cinnamon and Ubuntu's GNOME, but not on desktops
  without a tray (for example plain GNOME on Fedora). That is why closing the window
  minimises the app instead of quitting; use `Ctrl+Q` to quit.
- **macOS:**
  - Hotkeys and the clipboard need permission under System Settings → Privacy & Security →
    Accessibility and Input Monitoring.
  - To detect a repeated copy of the same text, install `pyobjc-framework-Cocoa`.
  - The tray icon may be limited.

## Data and privacy

- The desktop ledger is stored in `~/.clipveil.json`, so restoring works after a restart.
- **Passwords, tokens and keys are never written to disk** or included in exports; they
  live in memory while the app runs. After a restart, tokens such as `PASSWORD_1` are no
  longer restored and stay as they are.
- **The ledger and exported ledgers contain real IPs, hostnames and emails in plain text.**
  Don't share them or commit them; `.gitignore` already excludes them.
- Glance at the masked output or the Ledger before sending. Detection is heuristic and not
  a 100% guarantee.

## Troubleshooting

- **The app does not start:** an error dialog appears, and the details are written to
  `clipveil-error.log` in your home folder. Sharing that file makes the problem quick to
  find.
- **Hotkeys don't work:** if the status card shows "✕ Hotkeys", run `pip install pynput`.
  The Auto-watch switch works without hotkeys.
- **"✕ Clipboard":** `pip install pyperclip`; on Linux also `sudo apt install xclip`.
- **Nothing happens when copying:** Auto-watch must be on, and the text must contain
  something to mask.
- **Python 3.14:** if some packages have no ready-made wheels for it yet, use Python 3.12 or
  3.13.
