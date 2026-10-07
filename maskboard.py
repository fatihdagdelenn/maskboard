#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MaskBoard — mask IPs, hostnames, users, containers and secrets in logs/configs before
pasting them into an AI assistant, then restore the AI's answer to the real values.
Everything runs locally.

  python maskboard.py                         run the desktop app
  python maskboard.py --export-icon app.ico   write the icon (.ico or .png)

Hotkeys (needs pynput): Ctrl+Alt+A mask clipboard · Ctrl+Alt+R restore clipboard ·
Ctrl+Alt+T toggle auto-watch.
"""

import ipaddress, json, locale, os, re, sys, threading, time, unicodedata

try:
    import pyperclip
except ImportError:
    pyperclip = None
try:
    from pynput import keyboard
except Exception:
    keyboard = None


def _import_pystray():
    try:
        import pystray
        return pystray
    except Exception:
        pass
    # Linux without GTK/AppIndicator: fall back to the plain X11 backend
    if sys.platform.startswith("linux") and os.environ.get("DISPLAY"):
        for m in [k for k in sys.modules if k == "pystray" or k.startswith("pystray.")]:
            del sys.modules[m]
        os.environ["PYSTRAY_BACKEND"] = "xorg"
        try:
            import pystray
            return pystray
        except Exception:
            pass
    return None
pystray = _import_pystray()

APP_NAME = "MaskBoard"
HOME = os.path.expanduser("~")
STORE = os.path.join(HOME, ".maskboard.json")
LEGACY_STORES = [os.path.join(HOME, n) for n in (".clipveil.json", ".anonim_ajan.json")]   # earlier names

# =====================================================================
#  ENGINE
# =====================================================================
# Sensitive values become typed, numbered tokens (IP_PRIV_1, HOST_2, PASSWORD_1 …).
# Tokens are deliberately not wrapped in <…>: chat UIs may swallow them as HTML.
# Detection runs context first (prompts, ip a, docker ps, /etc/hosts, journal,
# connection strings), then generic patterns. Names learned from context keep their
# token in later messages too.

MASK_SYSTEM_USERS = False
SYSTEM_USERS = set("""root admin administrator sa sys system postgres mysql mariadb oracle redis
    mongodb www-data nginx apache httpd nobody daemon bin sync games man lp mail news uucp proxy
    backup list irc gnats systemd-network systemd-resolve systemd-timesync messagebus syslog sshd
    ubuntu debian centos ec2-user fedora pi vagrant jboss wildfly tomcat jenkins gitlab-runner git
    docker sudo wheel users staff adm deploy ansible guest test user operator elasticsearch kibana
    grafana prometheus rabbitmq zookeeper kafka hdfs yarn hive spark nagios zabbix""".split())

# Older releases used these prefixes; they still restore and are upgraded on the next mask.
LEGACY_PREFIXES = {"IP", "IPV6", "KULLANICI", "PROJE", "PAROLA", "ANAHTAR", "AYAR", "OZEL", "TARIH"}
TOKEN_PREFIXES = ["NATIONAL_ID", "IPV6_PRIV", "IPV6_PUB", "IP_PRIV", "IP_PUB", "CONTAINER", "PASSWORD", "PROJECT",
                  "DOMAIN", "SCHEMA", "SECRET", "CONFIG", "CUSTOM", "TOKEN", "IFACE", "HOST", "MAIL",
                  "JNDI", "USER", "DATE", "URL", "MAC", "DS", "DB"] + sorted(LEGACY_PREFIXES)
# Not part of a word (MYDB_1) or of an UPPER_CASE identifier (DB_HOST_1); IP_1 ≠ IP_10.
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?<![A-Z]_)(?:%s)_\d+(?!\d)" %
                      "|".join(sorted(TOKEN_PREFIXES, key=len, reverse=True)))
def is_token(s): return bool(TOKEN_RE.fullmatch(s or ""))

TYPE_PREFIX = {"mac": "MAC", "hostname": "HOST", "domain": "DOMAIN", "email": "MAIL", "date": "DATE",
               "custom": "CUSTOM", "user": "USER", "container": "CONTAINER", "project": "PROJECT",
               "iface": "IFACE", "url": "URL", "natid": "NATIONAL_ID"}

# On overlap at the same start position the higher priority wins.
PRIO = {"secret": 7, "custom": 6, "url": 5.5, "natid": 5.2, "email": 5, "container": 4.8, "project": 4.7, "iface": 4.6,
        "user": 4.5, "domain": 4, "date": 3.5, "ipv6": 3, "ipv4": 2, "mac": 1, "hostname": 0.5,
        "config": 0.3}
P_CONTEXT = 6.5
P_SPREAD = 0.6
P_ENTROPY = 0.45

PAT = {
    "ipv4":  re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    "ipv6":  re.compile(r"(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(?![0-9A-Fa-f:])"),
    "email": re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9\-])"),
    "domain":re.compile(r"(?<![A-Za-z0-9.@\-])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![A-Za-z0-9\-])"),
    "mac":   re.compile(r"(?<![0-9A-Fa-f:\-])(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:\-])"),
}

# ---- addresses ----
_PRIV_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fc00::/7", "fe80::/10")]
PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
WELL_KNOWN_NETS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                   "127.0.0.0/8", "0.0.0.0/0", "224.0.0.0/4", "240.0.0.0/4", "::/0", "fc00::/7",
                   "fe80::/10", "ff00::/8"}
BENIGN_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

def _ip_prefix(ip, v6=False):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "IPV6_PUB" if v6 else "IP_PUB"
    base = "IPV6" if a.version == 6 else "IP"
    priv = any(a in n for n in _PRIV_NETS if n.version == a.version)
    return base + ("_PRIV" if priv else "_PUB")

def _benign_ip(ip):
    """Loopback, unspecified, multicast, netmasks and public resolvers are left alone."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_unspecified or a.is_multicast: return True
    if a.version == 6: return a.is_reserved
    return ip.startswith("255.") or ip in PUBLIC_DNS

def _benign_mac(m): return m.lower().replace("-", ":") in BENIGN_MACS

# ---- dates (always recognised so they are never mistaken for IPs/hosts) ----
_D = r"(?:0?[1-9]|[12]\d|3[01])"
_M = r"(?:0?[1-9]|1[0-2])"
_Y = r"(?:19|20)\d{2}"
_MON = ("january|february|march|april|june|july|august|september|october|november|december|"
        "sept|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|"
        "ağustos|agustos|şubat|subat|haziran|temmuz|aralık|aralik|nisan|mayıs|mayis|kasım|kasim|"
        "eylül|eylul|ocak|mart|ekim")
_DATE_BODY = "|".join([
    _Y + r"([\-/.])" + _M + r"\1" + _D,                              # 2026-10-01
    _D + r"([./\-])" + _M + r"\2" + _Y,                               # 01.10.2026
    r"(?:0[1-9]|[12]\d|3[01])([./])(?:0[1-9]|1[0-2])\3\d{2}",         # 01.10.26 (not 7.4.12)
    _D + r"[ \-/.]?(?:" + _MON + r")\.?[ \-/.,]*" + _Y,              # 01 Oct 2026
    r"(?:" + _MON + r")\.?[ \-]" + _D + r",?[ \-]" + _Y,              # Oct 1, 2026
])
DATE_RE = re.compile(r"(?<!\d)(?<!\d[.\-/])(?:" + _DATE_BODY + r")(?!\d|[.\-/]\d)", re.I)

# ---- secrets ----
_PW_CORE = (r"passwd|password|passwort|passphrase|pwd|kennwort|contraseña|contrasena|motdepasse|"
            r"mot_de_passe|senha|wachtwoord|hasło|haslo|lösenord|losenord|şifre|sifre|parola")
_TOK_CORE = (r"client[_\-]?secret|secret[_\-]?key|private[_\-]?key|access[_\-]?key|api[_\-]?key|"
             r"apikey|access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|credentials?|secret|token")
_KV_SEP = r"[\"']?[ \t]*(?::=|=>|->|[:=>])[ \t]*"
_KV_VAL = r"(?:(?P<q>[\"'])(?P<v1>[^\"'\r\n]{1,256})(?P=q)|(?P<v2>[^\s\"'<>,;&)}\]]{1,256}))"
SECRET_KV_RE = re.compile(
    r"(?<![\w.\-/])(?P<key>[\w.\-]*?(?P<core>" + _PW_CORE + "|" + _TOK_CORE + r")[\w.\-]*"
    r"|[\w.\-]*[_.\-](?P<suf>key|pass)|pass)" + _KV_SEP + _KV_VAL, re.I)
# Keys ending like this describe a secret rather than hold one (token_url, password_min_length).
SECRET_KEY_META = ("file", "path", "dir", "url", "uri", "length", "len", "size", "count", "ttl",
                   "timeout", "expiry", "expires", "expiration", "min", "max", "policy", "type",
                   "name", "id", "enabled", "required", "header", "prefix", "field", "param",
                   "algorithm", "alg", "rotation", "store", "location", "hint", "age", "format",
                   "mode", "method", "scope", "lifetime", "interval", "reset", "changed")
SECRET_KEY_NOT = ("primary_key", "foreign_key", "sort_key", "partition_key", "public_key", "hash_key",
                  "range_key", "cache_key", "row_key", "pubkey", "public-key", "publickey")
SECRET_CLI_RE = re.compile(r"(?<![\w\-])--?(?P<core>password|passwd|pass|pwd|token|api-key|secret)"
                           r"[ =](?P<v>[^\s\"']{2,256})", re.I)
CURL_USER_RE = re.compile(r"\bcurl\b[^\n|;]*?\s(?:-u|--user)\s+[\"']?(?P<u>[^:\s'\"]+):(?P<p>[^\s'\"]+)")
SECRET_BEARER_RE = re.compile(r"\b(?:Bearer|Basic)\s+(?P<v>[A-Za-z0-9\-._~+/]{8,}=*)")
SECRET_PEM_RE = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----\r?\n(?P<body>[\s\S]+?)\r?\n-----END \1PRIVATE KEY-----")
SECRET_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                         # AWS
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),                        # GitHub
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),                         # GitLab
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),                     # Slack
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),                            # Google
    re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),              # Stripe
    re.compile(r"\bhvs\.[A-Za-z0-9_\-]{20,}\b"),                          # Vault
    re.compile(r"\beyJ[\w\-]{8,}\.[\w\-]{8,}\.[\w\-]{8,}\b"),            # JWT
]
SECRET_SKIP = {"null", "none", "nil", "true", "false", "undefined", "empty", "yes", "no", "required",
               "optional", "string", "hidden", "masked", "redacted", "bearer", "basic"}
ENTROPY_RE = re.compile(r"(?<![\w+/=\-.])[A-Za-z0-9+/_\-]{20,}={0,2}(?![\w+/=\-.])")

# ---- Turkish national ID (T.C. kimlik no): 11 digits validated by its two check digits ----
NATID_RE = re.compile(r"(?<![0-9A-Za-z.,])[1-9][0-9]{10}(?![0-9A-Za-z]|[.,][0-9])")

def _natid_ok(s):
    d = [int(c) for c in s]
    return ((sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10 == d[9]) and sum(d[:10]) % 10 == d[10]

# ---- connection strings: scheme://user:password@host:port/db ----
CONN_RE = re.compile(r"\b(?P<scheme>[a-z][a-z0-9+.\-]*)://(?:(?P<user>[^\s:/@'\"]*)(?::(?P<pw>[^\s/@'\"]*))?@)?"
                     r"(?P<host>\[[0-9A-Fa-f:]+\]|[^\s/:?#,;'\"@\[\]]+)(?::\d+)?(?:/(?P<db>[A-Za-z_][\w\-]*))?", re.I)
DB_SCHEMES = {"postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "sqlserver", "mssql",
              "oracle", "db2", "clickhouse", "cockroachdb", "redshift", "snowflake", "cassandra"}

def _secret_prefix(core=None, suf=None):
    c = (core or suf or "").lower()
    if re.fullmatch(_PW_CORE + "|pass", c): return "PASSWORD"
    if "private" in c: return "SECRET"
    return "TOKEN"

def _secret_ok(v, prefix):
    if not v or len(v) < 2 or is_token(v): return False
    if v.lower() in SECRET_SKIP or set(v) <= set("*•#x?."): return False    # empty or already masked
    if re.match(r"^(\$\{|%\(|\{\{|<|\$[A-Z_])", v): return False             # ${DB_PASS} references
    if prefix == "TOKEN" and v.isdigit(): return False                      # max_tokens: 4096
    return True

def _entropy(s):
    from math import log2
    n = len(s); freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    return -sum(c / n * log2(c / n) for c in freq.values())

def _looks_random(s):
    """Fallback secret check: 20+ chars, mixed case + digits, high entropy; not hex IDs or CamelCase."""
    if s.startswith("/") or s.count("/") > 2 or is_token(s): return False
    if re.fullmatch(r"[0-9a-fA-F\-]+", s): return False
    if not (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s) and re.search(r"\d", s)): return False
    if re.search(r"(?:[A-Z][a-z]{2,}){3,}", s): return False
    return _entropy(s) >= 3.6

# ---- users ----
_USER_VAL = (r"(?:(?P<q>[\"'])(?P<v1>[^\"'\r\n<>()]{1,64})(?P=q)|"
             r"(?P<v2>[^\s\"'<>,;&(){}\[\]|]{1,64}))")
USER_KV_RE = re.compile(
    r"(?<![\w.\-/])(?P<key>[\w.\-]*?(?:user(?:[_\-]?name)?|login|logname|user[ _\-]?id|uid))" + _KV_SEP + _USER_VAL, re.I)
USER_ID_RE = re.compile(r"(?<![\w])(?:uid|gid|groups|euid)=(?:\d+\([\w.\-]+\),?)+")
USER_ID_ONE = re.compile(r"\d+\((?P<u>[\w.\-]+)\)")
USER_CLI_RE = re.compile(r"(?<![\w\-])--(?:user|username|login)(?:=|\s+)[\"']?(?P<v>[\w.\-@]+)")
USER_U_RE = re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb|psql|pg_dump|pg_dumpall|pg_restore|createdb|"
                       r"dropdb|sudo|su|crontab|mongosh|mongo|redis-cli|sqlcmd|influx|(?:docker|podman)\s+(?:exec|run))"
                       r"\b[^\n|;&]*?\s-[uU][ \t]*[\"']?(?P<v>[A-Za-z_][\w.\-@]*)")
SSH_RE = re.compile(r"\b(?:ssh|scp|sftp|rsync|ssh-copy-id|mosh)\b[^\n|;&]*?\s(?P<u>[A-Za-z_][\w.\-]*)@"
                    r"(?P<h>[A-Za-z0-9][\w.\-]*)")
HOME_RE = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\Users\\|\\\\Users\\\\)(?P<u>[A-Za-z_][\w.\-]*)")
SSHD_RE = re.compile(r"\b(?:Accepted \w+ for|Failed \w+ for(?: invalid user)?|Invalid user|"
                     r"session (?:opened|closed) for user|Disconnected from(?: invalid| authenticating)? user|"
                     r"pam_unix\([^)]*\): [^\n]*? user)\s+(?P<u>[A-Za-z_][\w.\-]*)")
SUDO_RE = re.compile(r"\bsudo(?:\[\d+\])?:\s+(?P<u>[A-Za-z_][\w.\-]*)\s+:")
USER_SKIP = {"unknown", "invalid", "none", "null", "anonymous", "public", "default", "shared",
             "all users", "everyone", "local", "remote", "true", "false"}

# ---- shell prompts and project directories ----
PROMPT_RE1 = re.compile(r"(?m)(?:^|(?<=[\s)\]]))(?P<u>[a-z_][\w.\-]{0,31})@(?P<h>[A-Za-z0-9][\w.\-]{0,62}):"
                        r"(?P<d>[^\s$#]*)[$#](?=\s|$)")
PROMPT_RE2 = re.compile(r"\[(?P<u>[a-z_][\w.\-]{0,31})@(?P<h>[A-Za-z0-9][\w.\-]{0,62})\s+(?P<d>[^\]\s]+)\]\s?[$#]")
PROMPT_PS = re.compile(r"(?m)^PS (?P<d>[A-Za-z]:\\[^>\n]*)>")
SYSTEM_PATHS = ("/var/lib", "/var/log", "/var/cache", "/var/spool", "/var/run", "/etc", "/usr", "/proc",
                "/sys", "/dev", "/run", "/boot", "/lib", "/bin", "/sbin", "/tmp", "/snap", "/nix")
DIR_CTX_RE = re.compile(r"\b(?:PWD|OLDPWD|working_dir|WorkingDir|workdir|project\.working_dir)[\"']?\s*[=:]\s*"
                        r"[\"']?(?P<d>/[^\s\"';,]+)")
DEPLOY_RE = re.compile(r"(?:Deployed|Undeployed|Replaced deployment|Starting deployment of|Stopped deployment|"
                       r"runtime-name\s*:)\s*\\?\"(?P<p>[A-Za-z][\w\-]*?)\.(?:war|ear|jar|rar|sar)\\?\"")
UPSTREAM_RE = re.compile(r"\bupstream\s+(?P<n>[A-Za-z][\w.\-]*)\s*\{")
UPSTREAM_NAME = re.compile(r"([A-Za-z][A-Za-z0-9]*?)[_\-](?:backend|upstream|app|api|web|servers?|pool)$")
SUBDOMAIN_COMMON = set("""www mail smtp imap pop pop3 ftp sftp vpn portal intranet extranet api app apps
    auth sso login cdn static assets img images media admin panel dev test stage staging prod beta
    demo docs wiki git gitlab jenkins grafana kibana monitor status shop store blog news web ns ns1 ns2
    mx owa webmail remote secure cloud files support help crm erp hr db sql ldap ad dc proxy gateway
    registry repo nexus harbor console""".split())
STD_DIRS = set("""~ / root home etc var opt srv tmp usr local bin sbin lib lib64 log logs data app apps
    src code projects project proje projeler work workspace repos repo git docker compose deploy backup
    backups www html conf config configs nginx jboss wildfly standalone configuration deployments
    Desktop Downloads Documents Masaüstü İndirilenler Belgeler build dist target node_modules venv .venv
    scripts test tests docs mnt media run dev proc sys boot cache spool mail share include system32
    Windows Users sites-enabled sites-available conf.d ssl certs secrets volumes""".split())
COMMON_WORDS = set("""app api web www db data test prod dev stage staging main master default
    backend frontend server client service worker proxy cache mail admin user users home public
    private local remote config docs src lib bin log logs tmp root""".split())

# ---- syslog/journal, /etc/hosts ----
SYSLOG_RE = re.compile(r"(?m)^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
                       r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
                       r"(?P<h>[A-Za-z0-9][\w.\-]{0,62})\s+(?P<p>[A-Za-z][\w\-./@]*)(?:\[\d+\])?:\s")
LOG_LEVELS = {"INFO", "WARN", "WARNING", "ERROR", "DEBUG", "TRACE", "FATAL", "NOTICE", "CRIT",
              "CRITICAL", "SEVERE", "FINE", "FINER", "FINEST", "ALERT", "EMERG", "ERR"}
HOSTS_RE = re.compile(r"(?m)^[ \t]*(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)[ \t]+"
                      r"(?P<names>[A-Za-z0-9][\w.\-]*(?:[ \t]+[A-Za-z0-9][\w.\-]*){0,7})[ \t\r]*(?:#[^\n]*)?$")
HOST_KEEP = {"localhost", "localhost.localdomain", "localdomain", "broadcasthost", "ip6-localhost",
             "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
             "ip6-allhosts", "host.docker.internal", "gateway.docker.internal"}

# ---- network interfaces ----
IFACE_STD_RE = re.compile(r"(?:lo|eth\d+|ens\d+(?:f\d+)?(?:np\d+)?|enp\d+s\d+(?:f\d+)?(?:np\d+)?|eno\d+|"
                          r"enx[0-9a-f]{12}|em\d+|p\d+p\d+|wlan\d+|wlp\d+s\d+|wlo\d+|docker\d+|veth[0-9a-f]+|"
                          r"virbr\d+(?:-nic)?|tun\d+|tap\d+|wg\d+|bond\d+|team\d+|cni\d+|flannel\.\d+|"
                          r"cali[0-9a-f]+|tunl\d+|vxlan\.calico|vxlan\d*|kube-ipvs\d+|kube-bridge|br\d+|if\d+|"
                          r"ip6tnl\d+|sit\d+|gre\d+|gretap\d+|erspan\d+|ip_vti\d+|ip6_vti\d+|ip6gre\d+|"
                          r"lxcbr\d+|lxdbr\d+|podman\d+|cilium_\w+|nodelocaldns|dummy\d+|ovs-system|br-int|"
                          r"br-ex|ens\d+\.\d+|eth\d+\.\d+)", re.I)
def is_std_iface(n): return bool(IFACE_STD_RE.fullmatch(n or ""))
IFACE_LINE_RE = re.compile(r"(?m)^\d+:\s+(?P<i>[^\s:@]+)(?:@(?P<peer>[^\s:]+))?:\s+<")
IFCONFIG_RE = re.compile(r"(?m)^(?P<i>[A-Za-z][\w.\-]*?):?\s+(?:flags=|Link encap)")
IFACE_REF_RE = re.compile(r"\b(?:dev|master|iif|oif|iface|interface|vlan-raw-device|bridge_ports)\s+"
                          r"(?P<i>[A-Za-z][\w.\-]*)")
BRIDGE_RE = re.compile(r"\bbr-[0-9a-f]{12}\b")

# ---- containers / compose projects ----
DOCKER_PS_HDR = re.compile(r"(?m)^CONTAINER ID\s+IMAGE\s+.*\bNAMES[ \t\r]*$")
DOCKER_IMAGES_HDR = re.compile(r"(?m)^REPOSITORY\s+TAG\s+IMAGE ID\b[^\n]*$")
OFFICIAL_IMAGES = set("""postgres mysql mariadb redis valkey nginx httpd node python alpine ubuntu debian
    busybox mongo mongo-express rabbitmq elasticsearch kibana logstash grafana prometheus traefik caddy
    memcached wordpress php golang openjdk eclipse-temurin amazoncorretto ibmjava jenkins sonarqube
    registry adminer haproxy consul vault influxdb telegraf zookeeper kafka cassandra couchdb neo4j
    nextcloud gitea ghost drupal joomla tomcat jetty centos fedora rockylinux almalinux oraclelinux
    amazonlinux docker hello-world swarm solr nats etcd minio keycloak ruby rust perl gcc maven
    gradle composer bash vaultwarden portainer pgadmin4 phpmyadmin percona clickhouse""".split())
CONTAINER_NAME_RE = re.compile(r"(?:--name[ =][\"']?|container_name:[ \t]*[\"']?|\"Name\"\s*:\s*\"/)"
                               r"(?P<n>[A-Za-z0-9][\w.\-]*)")
DOCKER_CMD_RE = re.compile(
    r"\b(?:docker|podman)\s+(?:container\s+)?(?:logs|exec|inspect|restart|stop|start|rm|kill|attach|top|"
    r"stats|port|cp|update|wait|pause|unpause|rename|commit|diff|export)\b"
    r"(?:\s+(?:(?:--(?:tail|since|until|user|env|workdir|env-file|format|time|signal|detach-keys)|-[nuew])"
    r"(?:=|\s+)\S+|-{1,2}[\w\-]+(?:=\S+)?))*\s+(?P<n>[A-Za-z0-9][\w.\-]*)")
COMPOSE_PROJECT_RE = re.compile(
    r"(?:com\.docker\.compose\.project[\"']?\s*[:=]\s*[\"']?|COMPOSE_PROJECT_NAME[ \t]*=[ \t]*[\"']?|"
    r"\bdocker[ \-]compose\b[^\n]*?\s(?:-p|--project-name)[ =][\"']?)(?P<p>[A-Za-z0-9][\w.\-]*)")
COMPOSE_NAME_RE = re.compile(r"^(?P<p>[A-Za-z0-9][\w.\-]*?)[-_](?P<s>[a-z0-9][a-z0-9.]*)[-_](?P<n>\d+)$")
DOCKER_WORDS = {"bash", "sh", "zsh", "ash", "python", "node", "java", "psql", "mysql", "redis-cli",
                "cat", "ls", "env", "printenv", "true", "false"}

# ---- hostnames ----
HOST_BLOCK = set(["md5","md2","md4","sha1","sha2","sha3","sha224","sha256","sha384","sha512","ripemd160",
    "crc32","adler32","base64","base32","utf8","utf16","utf32","utf8mb4","latin1","iso88591","x8664",
    "amd64","arm64","aarch64","armv7l","i386","i686","ppc64le","s390x","win32","win64","http2","http3",
    "h2","h2c","tls10","tls11","tls12","tls13","tlsv1","tlsv12","tlsv13","ssl2","ssl3","sslv3","ipv4",
    "ipv6","ip4","ip6","inet4","inet6","icmp6","icmpv6","tcp4","tcp6","udp4","udp6","raw6","ssh1","ssh2",
    "oauth2","ec2","s3","k8s","k3s","i18n","l10n","a11y","p2p","log4j","log4j2","ext2","ext3","ext4",
    "fat32","ntfs","rfc822","x509","pkcs1","pkcs7","pkcs8","pkcs11","pkcs12","p12","ed25519","ed448",
    "rsa1024","rsa2048","rsa4096","nistp256","nistp384","nistp521","secp256r1","secp384r1","prime256v1",
    "aes128","aes192","aes256","chacha20","poly1305","overlay2","cgroup2","cgroupv2","netns0","el7",
    "el8","el9","fc38","fc39","fc40","win10","win11","dotnet6","dotnet8","node18","node20","node22"])
KW_RE = re.compile(r"\b(?:hostname|nodename|node|computername|computer|dnsname|host|cn)\b\s*[:=]\s*[\"']?"
                   r"([A-Za-z][A-Za-z0-9\-]{1,62})[\"']?", re.I)
TOK_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*\b")
# Log noise that looks like a host: thread-12, pool-3, port8080 …
HOST_NOISE = {"thread","threads","pool","worker","workers","task","tasks","exec","executor",
    "nio","ajp","main","job","batch","session","sess","req","request","conn","connection",
    "tx","timer","scheduler","async","default","eventloop","loop","reactor","line","row","col",
    "page","step","item","port","pid","tid","build","rev","release","version","ver","attempt",
    "retry","try","phase","stage","part","chunk","index","idx","slot","queue","listener",
    "handler","consumer","producer","partition","offset","epoch","gen","generation","pts","tty"}
# Product prefixes: java17, jboss-eap-7, java-17-openjdk-amd64 …
HOST_PRODUCT = {"java","jdk","jre","jvm","openjdk","jboss","wildfly","eap","tomcat","spring",
    "hibernate","postgres","postgresql","pg","mysql","mariadb","mssql","oracle","ora","redis",
    "kafka","nginx","apache","httpd","centos","rhel","el","ubuntu","debian","windows","win",
    "python","py","npm","tls","tlsv","ssl","sslv","http","https","utf","iso","cp","sha",
    "md","ipv","rfc","cve","jsr","jep","log","slf","logback","junit","maven","gradle","v",
    "alpine","node","golang","go","php","ruby","dotnet","kernel","linux","fedora","rocky","alma"}

# ---- domains ----
# Real TLDs only, so org.jboss.as, server.log and Pool.java are not taken for domains.
TLDS = set("""com net org io co info biz tr uk de eu us gov edu mil int local lan internal
    intranet intra corp home localdomain cloud dev app ai tech systems online site xyz me nl fr
    it es ru ch at be se no dk fi cz gr ro hu az kz ua il ae sa qa in cn jp kr sg hk tw au nz ca
    br mx za arpa""".split())
TWO_LEVEL = set("""com.tr net.tr org.tr gov.tr edu.tr bel.tr k12.tr gen.tr av.tr bbs.tr
    co.uk org.uk ac.uk gov.uk com.au net.au co.jp co.kr com.br com.cn co.za co.in""".split())
BENIGN_DOMAINS = set("""example.com example.org example.net localhost.localdomain github.com
    gitlab.com stackoverflow.com google.com microsoft.com apple.com redhat.com oracle.com
    jboss.org wildfly.org apache.org python.org pypi.org npmjs.com npmjs.org maven.org spring.io
    openai.com anthropic.com claude.ai chatgpt.com ubuntu.com debian.org centos.org kernel.org
    mozilla.org w3.org ietf.org wikipedia.org docker.com docker.io kubernetes.io k8s.io ghcr.io
    quay.io gcr.io pkg.dev postgresql.org mysql.com mariadb.org cloudflare.com letsencrypt.org
    xmlsoap.org jcp.org sun.com java.com openjdk.org hibernate.org eclipse.org jakarta.ee
    alpinelinux.org fedoraproject.org rockylinux.org almalinux.org golang.org nodejs.org
    githubusercontent.com elastic.co hashicorp.com grafana.com prometheus.io nginx.org nginx.com
    googleapis.com gstatic.com""".split())

def _split_domain(d):
    """'app01.example.com.tr' → (['app01'], 'example.com.tr')"""
    labels = d.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]).lower() in TWO_LEVEL else 2
    return labels[:-n], ".".join(labels[-n:])

def _benign_domain(d):
    low = d.lower()
    return any(low == b or low.endswith("." + b) for b in BENIGN_DOMAINS)

def _valid_domain(d):
    tld = d.rsplit(".", 1)[-1]
    return tld == tld.lower() and tld in TLDS and not _benign_domain(d)

# ---- URLs: http(s)://… becomes a single URL_n ----
URL_RE = re.compile(r"\bhttps?://(?:\[[0-9A-Fa-f:.]+\]|[^\s<>\"'`(){}\[\]|\\^])+", re.I)
URL_PARTS_RE = re.compile(r"https?://(?:(?P<ui>[^/?#@]*)@)?(?P<host>\[[0-9A-Fa-f:.]+\]|[^/:?#]*)", re.I)
URL_SECRET_PARAM_RE = re.compile(r"[?&#;][\w.\-]*(?:pass|pwd|token|secret|key|auth|sig|session|code|credential)"
                                 r"[\w.\-]*=", re.I)

def _url_host(url):
    m = URL_PARTS_RE.match(url)
    return (m.group("host") or "") if m else ""

def _url_kind(url, text):
    """'mask' → URL_n · 'skip' → leave as is (localhost, public sites, nginx upstream) ·
    'split' → mask piece by piece, because a whole URL with credentials must not reach the ledger."""
    m = URL_PARTS_RE.match(url)
    if not m: return "skip"
    host = m.group("host") or ""
    if not host or host[0] in "$%{" or is_token(host): return "skip"
    bare = host.strip("[]")
    if bare.lower() == "localhost" or _benign_ip(bare) or _benign_domain(bare): return "skip"
    if "." not in host and re.search(r"\bupstream\s+" + re.escape(host) + r"\b", text): return "skip"
    if ":" in (m.group("ui") or "") or URL_SECRET_PARAM_RE.search(url): return "split"
    return "mask"

def _label_spreads(lbl):
    low = lbl.lower()
    return (len(lbl) >= 4 and low not in SUBDOMAIN_COMMON and low not in COMMON_WORDS
            and low not in HOST_PRODUCT and not re.search(r"\d", lbl))

def _host_spread_labels(v, typ):
    """Distinctive host labels inside a domain/URL, so a bare 'billing' is hidden after 'billing.example.com'."""
    h = _url_host(v) if typ == "url" else v
    if not h or h.startswith("[") or PAT["ipv4"].fullmatch(h): return []
    labels = _split_domain(h)[0] if "." in h else [h]
    return [lbl for lbl in labels if _label_spreads(lbl)]

# ---- config values ----
# Free keys match without a separator ("datasource jboss"); strict keys need ":", "=" or ">".
CFG_FREE = ["datasource name","datasource","data source","data-source","jndi name","jndi-name",
    "jndi","pool name","pool-name","database name","database-name","schema name","service name",
    "instance name","connection pool","connection-pool"]
CFG_STRICT = ["database","databasename","db name","db-name","dbname","db","schema","schema-name",
    "catalog","ds name","dsname","pool","servicename","service-name","sid","instance",
    "instance-name","realm","context root","context-root"]
def _cfg_alt(keys):
    return "|".join(r"\s+".join(re.escape(p) for p in k.split()) for k in sorted(keys, key=len, reverse=True))
_CFG_VAL = r"[ \t]*[\"']?([A-Za-z_][\w.\-\/:]*)[\"']?"
CFG_FREE_RE = re.compile(r"(?<!/)\b(" + _cfg_alt(CFG_FREE) + r")\b[ \t]*(?:[:=>]|:=|=>|->)?" + _CFG_VAL, re.I)
CFG_STRICT_RE = re.compile(r"(?<!/)\b(" + _cfg_alt(CFG_STRICT) + r")\b[ \t]*(?:[:=>]|:=|=>|->)" + _CFG_VAL, re.I)
CFG_ENV_RE = re.compile(r"(?<![\w.\-/])(?P<key>[A-Za-z0-9_.\-]*?(?:db[_\-]?name|database(?:[_\-]?name)?|"
                        r"postgres_db|mysql_database|schema(?:[_\-]?name)?|jndi[_\-]?name|"
                        r"datasource(?:[_\-]?name)?))[\"']?[ \t]*[=:][ \t]*[\"']?(?P<v>[A-Za-z_][\w.\-\/:]*)", re.I)
CFG_STOP = set(["is","are","was","were","be","been","the","a","an","of","for","to","in","on",
    "and","or","not","no","yes","true","false","null","none","name","value","type","this","that",
    "with","ise","olarak","bir","ve","veya","için","ile","adı","adi","ismi","olan","gibi"])
CFG_STOP |= {k.lower() for k in CFG_FREE + CFG_STRICT}
CFG_STOP |= {"jndi-name", "pool-name", "user-name", "enabled", "use-java-context", "statistics-enabled"}

def _cfg_prefix(key):
    k = re.sub(r"[\s_\-.]", "", key.lower())
    if "jndi" in k: return "JNDI"
    if "datasource" in k or k in ("dsname", "pool", "poolname", "connectionpool"): return "DS"
    if "schema" in k: return "SCHEMA"
    if any(x in k for x in ("database", "dbname", "postgresdb", "mysqldatabase")) or \
       k in ("db", "catalog", "sid", "servicename", "instance", "instancename"): return "DB"
    return "CONFIG"

ALL_TYPES = ("ipv4","ipv6","domain","url","hostname","mac","iface","email","user","natid","container",
             "config","secret","date","custom")
# Dates are recognised but kept by default: timelines matter when debugging.
DEFAULT_OFF = {"date"}
def default_opts(): return {t: t not in DEFAULT_OFF for t in ALL_TYPES}
OPT_OF = {"project": "container"}


def _user_ok(v):
    if not v or len(v) < 2 or v.isdigit() or is_token(v): return False
    low = v.lower()
    if low in USER_SKIP or "/" in v or "$" in v or "{" in v: return False
    return MASK_SYSTEM_USERS or low not in SYSTEM_USERS

def _host_label_ok(v):
    if not v or len(v) < 2 or is_token(v) or v.isdigit(): return False
    low = v.lower()
    if low in HOST_KEEP or low in HOST_BLOCK or v.upper() in LOG_LEVELS or is_std_iface(v): return False
    return not re.fullmatch(r"[0-9a-f]{12}|[0-9a-f]{64}", low)              # container IDs

def _looks_like_host(tok):
    if len(tok) < 3 or len(tok) > 63 or not re.search(r"\d", tok): return False
    low = tok.lower()
    if low.replace("-", "") in HOST_BLOCK or low in HOST_KEEP or is_std_iface(tok): return False
    if re.search(r"ipv[46]|ip6|inet6", low): return False
    m = re.match(r"[a-z]+", low)
    first = m.group(0) if m else ""
    if first in HOST_NOISE or first in HOST_PRODUCT: return False
    if not re.search(r"[a-z]", tok) and re.search(r"\d{4,}", tok): return False   # WFLYCTL0013, ORA-00942
    if re.fullmatch(r"[0-9a-f\-]{8,}", low): return False                        # hash / UUID fragment
    return "-" in tok or len(first) >= 2

def _bounded(v):
    return re.compile(r"(?<![A-Za-z0-9._\-\/])" + re.escape(v) + r"(?![A-Za-z0-9_\-\/]|\.[A-Za-z0-9])")

def _spread_re(v):
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])")

def _token_fits(text, s, e):
    """True if a token placed at text[s:e] would still be read as a token when restoring."""
    lo = max(0, s - 2)
    m = TOKEN_RE.match(text[lo:s] + "CUSTOM_9" + text[e:e + 1], s - lo)
    return bool(m) and m.end() == s - lo + 8

def _part_break(a, b):
    """Is there an identifier-part boundary between characters a and b (snake_case, camelCase, letter|digit)?"""
    if not (a.isalnum() and b.isalnum()): return True
    if a.isalpha() != b.isalpha(): return True
    return unicodedata.category(a) == "Ll" and unicodedata.category(b) == "Lu"

def _custom_span(text, s, e):
    """Where to mask a custom term found at text[s:e]: the term itself when it is a whole word or an
    identifier part (ACME_Prod, AcmeUser), the whole identifier when a token there would not restore
    (X_ACME, ACME2024), or None when the term sits inside a word (net in network)."""
    if (s > 0 and not _part_break(text[s - 1], text[s])) or \
       (e < len(text) and not _part_break(text[e - 1], text[e])):
        return None
    if _token_fits(text, s, e): return s, e
    word = lambda ch: ch.isalnum() or ch == "_"
    while s > 0 and word(text[s - 1]): s -= 1
    while e < len(text) and word(text[e]): e += 1
    return (s, e) if _token_fits(text, s, e) else None


class Mapper:
    """Real value ↔ token ledger. Secrets live in memory only; store=None never touches disk."""
    def __init__(self, store="__default__"):
        self.store = STORE if store == "__default__" else store
        self.lock = threading.RLock()
        self._reset()
        self.custom_terms = []
        self.settings = {}
        self.load()

    def _reset(self):
        self.entries = []          # [{real, fake, type, secret?, prop?}]
        self.real_to_fake = {}
        self.by_real = {}
        self.secret_map = {}
        self.tok = {}              # token → real
        self.counters = {}         # prefix → last number

    def _token(self, prefix):
        n = self.counters.get(prefix, 0) + 1
        self.counters[prefix] = n
        return "%s_%d" % (prefix, n)

    def _register(self, real, typ, prefix, secret=False, prop=False):
        m = self.secret_map if secret else self.real_to_fake
        if real in m and not (not secret and self._should_upgrade(m[real], prefix)):
            if prop and not secret and real in self.by_real:
                self.by_real[real]["prop"] = True
            return m[real]
        t = self._token(prefix)
        m[real] = t; self.tok[t] = real
        e = {"real": real, "fake": t, "type": typ}
        if secret: e["secret"] = True
        if prop: e["prop"] = True
        self.entries.append(e)
        if not secret: self.by_real[real] = e
        return t

    @staticmethod
    def _should_upgrade(old, prefix):
        """Give a new token when the stored one is from an older release or a vaguer type.
        The old token stays in the ledger, so old AI answers still restore."""
        if not is_token(old): return True
        op = old.rsplit("_", 1)[0]
        if op == prefix: return False
        if op in LEGACY_PREFIXES: return True
        return op == "HOST" and prefix in ("IFACE", "CONTAINER", "PROJECT", "USER")

    def _get_fake(self, value, typ, prefix=None, prop=False):
        if typ == "domain":
            return self._register(value, "domain", "DOMAIN")
        if typ in ("ipv4", "ipv6"):
            return self._register(value, typ, _ip_prefix(value, typ == "ipv6"))
        if typ == "secret":
            return self._register(value, typ, prefix or "PASSWORD", secret=True)
        return self._register(value, typ, prefix or TYPE_PREFIX.get(typ, "CONFIG"), prop=prop)

    def _collect(self, text, opts=None):
        """Find sensitive values: [(start, end, value, type, prefix, spreads)]. Existing tokens are left alone."""
        opts = dict(default_opts(), **(opts or {}))
        on = lambda typ: opts.get(OPT_OF.get(typ, typ), False)
        found = []          # (s, e, v, typ, prefix, prio, prop)
        learned = {}        # names learned from context in this text: value → (type, prefix)

        def add(s, e, v, typ, prefix=None, prio=None, prop=False):
            if not on(typ) or s >= e: return
            found.append((s, e, v, typ, prefix, PRIO[typ] if prio is None else prio, prop))
            if prop: learned.setdefault(v, (typ, prefix))

        def add_host(s, v, prio, prop=True):
            if "." in v and _valid_domain(v):
                add(s, s + len(v), v, "domain", prio=prio)
            elif "." in v and _benign_domain(v):
                return
            elif _host_label_ok(v):
                add(s, s + len(v), v, "hostname", prio=prio, prop=prop)

        def add_user(s, v, prio=None):
            if _user_ok(v): add(s, s + len(v), v, "user", prio=prio, prop=True)

        def add_container(s, name, prio=None):
            if not name or is_token(name) or name in DOCKER_WORDS or re.fullmatch(r"[0-9a-f]{12,64}", name):
                return
            m = COMPOSE_NAME_RE.match(name)
            if m and len(m.group("p")) >= 2:                          # shop-web-1 → PROJECT_1-web-1
                add(s, s + len(m.group("p")), m.group("p"), "project", prio=prio, prop=True)
            else:
                add(s, s + len(name), name, "container", prio=prio, prop=True)

        # 1) secrets
        if on("secret"):
            secrets = {}
            def add_secret(s, v, p):
                add(s, s + len(v), v, "secret", p); secrets[v] = p
            for m in SECRET_KV_RE.finditer(text):
                key = m.group("key"); kl = key.lower()
                if kl.endswith(SECRET_KEY_META) or kl.endswith(SECRET_KEY_NOT): continue
                p = _secret_prefix(m.group("core"), m.group("suf") or ("pass" if kl == "pass" else None))
                g = "v1" if m.group("v1") is not None else "v2"
                v = m.group(g)
                if g == "v2": v = v.rstrip(".:")
                if key in ("PWD", "OLDPWD") and v.startswith("/"): continue
                if _secret_ok(v, p): add_secret(m.start(g), v, p)
            for m in SECRET_CLI_RE.finditer(text):
                p = _secret_prefix(m.group("core")); v = m.group("v")
                if _secret_ok(v, p): add_secret(m.start("v"), v, p)
            for m in CURL_USER_RE.finditer(text):
                add_user(m.start("u"), m.group("u"))
                if _secret_ok(m.group("p"), "PASSWORD"): add_secret(m.start("p"), m.group("p"), "PASSWORD")
            for m in SECRET_BEARER_RE.finditer(text):
                add_secret(m.start("v"), m.group("v"), "TOKEN")
            for m in SECRET_PEM_RE.finditer(text):
                add(m.start("body"), m.end("body"), m.group("body"), "secret", "SECRET")
            for rx in SECRET_PATTERNS:
                for m in rx.finditer(text):
                    add_secret(m.start(), m.group(0), "TOKEN")
            for m in ENTROPY_RE.finditer(text):
                if _looks_random(m.group(0)):
                    add(m.start(), m.end(), m.group(0), "secret", "TOKEN", prio=P_ENTROPY)
            for v, p in list(secrets.items()):                      # the same secret elsewhere in the text
                if len(v) >= 6:
                    for m in _bounded(v).finditer(text): add(m.start(), m.end(), v, "secret", p)

        # 2) connection strings
        conn_dbs = {}
        for m in CONN_RE.finditer(text):
            if m.group("user"): add_user(m.start("user"), m.group("user"), prio=P_CONTEXT)
            pw = m.group("pw")
            if pw and _secret_ok(pw, "PASSWORD"):
                add(m.start("pw"), m.end("pw"), pw, "secret", "PASSWORD", prio=8)
            h = m.group("host")
            if h and not is_token(h) and not PAT["ipv4"].fullmatch(h) and not h.startswith("["):
                if "." in h and _valid_domain(h):
                    add(m.start("host"), m.end("host"), h, "domain", prio=P_CONTEXT)
                elif "." not in h and _looks_like_host(h):
                    add(m.start("host"), m.end("host"), h, "hostname", prio=P_CONTEXT)
            db = m.group("db")
            if db and m.group("scheme").lower() in DB_SCHEMES and not is_token(db):
                add(m.start("db"), m.end("db"), db, "config", "DB", prio=P_CONTEXT)
                conn_dbs[db] = "DB"

        # 3) shell prompts, working directories, deployments, nginx upstreams
        def prompt_dir(d, base):
            d = d.rstrip("/\\")
            if any(d == sp or d.startswith(sp + "/") for sp in SYSTEM_PATHS): return
            name = re.split(r"[/\\]", d)[-1] if d else ""
            low = name.lower()
            if name and name not in STD_DIRS and len(name) >= 3 and not name.startswith("~") \
               and not is_token(name) and low not in COMMON_WORDS and low not in HOST_PRODUCT \
               and _user_ok(name) and not (home_user and name == home_user):
                add(base + len(d) - len(name), base + len(d), name, "project", prio=P_CONTEXT, prop=True)
        home_user = None
        for rx in (PROMPT_RE1, PROMPT_RE2):
            for m in rx.finditer(text):
                if not is_token(m.group("u")): add_user(m.start("u"), m.group("u"), prio=P_CONTEXT)
                if not is_token(m.group("h")): add_host(m.start("h"), m.group("h"), P_CONTEXT)
                prompt_dir(m.group("d"), m.start("d"))
        for m in PROMPT_PS.finditer(text):
            prompt_dir(m.group("d"), m.start("d"))
        for m in DIR_CTX_RE.finditer(text):
            hm = HOME_RE.search(m.group("d")); home_user = hm.group("u") if hm else None
            prompt_dir(m.group("d"), m.start("d"))
        home_user = None
        for m in DEPLOY_RE.finditer(text):
            if not is_token(m.group("p")):
                add(m.start("p"), m.end("p"), m.group("p"), "project", prop=True)
        for m in UPSTREAM_RE.finditer(text):
            n = m.group("n")
            if not is_token(n) and n.lower() not in COMMON_WORDS:
                cm = UPSTREAM_NAME.match(n)
                if cm and _label_spreads(cm.group(1)):
                    add(m.start("n"), m.start("n") + len(cm.group(1)), cm.group(1), "project", prop=True)

        # 4) users
        for m in HOME_RE.finditer(text):
            add_user(m.start("u"), m.group("u"))
        for m in USER_KV_RE.finditer(text):
            g = "v1" if m.group("v1") is not None else "v2"
            add_user(m.start(g), m.group(g).rstrip(".:"))
        for m in USER_ID_RE.finditer(text):
            for u in USER_ID_ONE.finditer(m.group(0)):
                add_user(m.start() + u.start("u"), u.group("u"))
        for rx in (USER_CLI_RE, USER_U_RE):
            for m in rx.finditer(text): add_user(m.start("v"), m.group("v"))
        for rx in (SSHD_RE, SUDO_RE):
            for m in rx.finditer(text): add_user(m.start("u"), m.group("u"))
        for m in SSH_RE.finditer(text):
            add_user(m.start("u"), m.group("u"), prio=P_CONTEXT)
            add_host(m.start("h"), m.group("h"), P_CONTEXT)

        # 5) host contexts: syslog/journal, /etc/hosts
        for m in SYSLOG_RE.finditer(text):
            if m.group("h").upper() not in LOG_LEVELS: add_host(m.start("h"), m.group("h"), P_CONTEXT)
        for m in HOSTS_RE.finditer(text):
            if not (PAT["ipv4"].fullmatch(m.group("ip")) or PAT["ipv6"].fullmatch(m.group("ip"))): continue
            off = m.start("names")
            for n in re.finditer(r"\S+", m.group("names")):
                add_host(off + n.start(), n.group(0), P_CONTEXT)

        # 6) network interfaces
        def add_iface(s, name):
            if name and not is_std_iface(name) and not is_token(name):
                add(s, s + len(name), name, "iface", prop=True)
        for m in IFACE_LINE_RE.finditer(text): add_iface(m.start("i"), m.group("i"))
        for m in IFCONFIG_RE.finditer(text): add_iface(m.start("i"), m.group("i"))
        for m in IFACE_REF_RE.finditer(text):
            if re.search(r"[\d\-]", m.group("i")): add_iface(m.start("i"), m.group("i"))
        for m in BRIDGE_RE.finditer(text): add_iface(m.start(), m.group(0))

        # 7) containers and compose projects
        for m in COMPOSE_PROJECT_RE.finditer(text):
            p = m.group("p")
            if not is_token(p) and len(p) >= 2:
                add(m.start("p"), m.end("p"), p, "project", prop=True)
        for rx in (CONTAINER_NAME_RE, DOCKER_CMD_RE):
            for m in rx.finditer(text): add_container(m.start("n"), m.group("n"))
        def image_parts(img):
            """'ghcr.io/x/app:1.2' → (repo, public?, local?)"""
            repo = re.split(r"[:@]", img, 1)[0] if not img.startswith("[") else img
            first = repo.split("/")[0]
            if "/" in repo and ("." in first or ":" in first or first == "localhost"):
                return repo, _benign_domain(first), False
            if "/" in repo:                                           # Docker Hub org/image
                return repo, True, False
            return repo, repo in OFFICIAL_IMAGES, repo not in OFFICIAL_IMAGES
        def add_local_image(s, repo, cname=None):
            """Local images are user-specific: 'proj-svc' masks the project part, otherwise the whole name."""
            cm = COMPOSE_NAME_RE.match(cname or "")
            if cm and repo in (cm.group("p") + "-" + cm.group("s"), cm.group("p") + "_" + cm.group("s")):
                add(s, s + len(cm.group("p")), cm.group("p"), "project", prop=True)
            elif not is_token(repo) and len(repo) >= 3:
                add(s, s + len(repo), repo, "project", prop=True)
        for h in DOCKER_PS_HDR.finditer(text):
            pos = h.end() + 1
            for line in text[pos:].split("\n"):
                row = re.match(r"([0-9a-f]{12})\s+(?P<img>\S+)", line)
                if not row: break
                last = re.search(r"(\S+)\s*$", line)
                names = list(re.finditer(r"[^,\s]+", last.group(1))) if last else []
                img = row.group("img"); repo, public, local = image_parts(img)
                if local and not is_token(img):
                    add_local_image(pos + row.start("img"), repo, names[0].group(0) if names else None)
                for nm in names:
                    n = nm.group(0)
                    if public and n == repo.split("/")[-1]: continue     # open-webui from …/open-webui
                    add_container(pos + last.start(1) + nm.start(), n)
                pos += len(line) + 1
        for h in DOCKER_IMAGES_HDR.finditer(text):
            pos = h.end() + 1
            for line in text[pos:].split("\n"):
                row = re.match(r"(?P<repo>\S+)\s+\S+\s+[0-9a-f]{12}\s", line)
                if not row: break
                repo, public, local = image_parts(row.group("repo"))
                if local and repo != "<none>": add_local_image(pos, repo)
                pos += len(line) + 1

        # 8) custom terms (case-insensitive) and national IDs
        for term in sorted([t for t in self.custom_terms if t], key=len, reverse=True):
            for m in re.finditer(re.escape(term), text, re.I):
                span = _custom_span(text, m.start(), m.end())
                if span: add(span[0], span[1], text[span[0]:span[1]], "custom")
        for m in NATID_RE.finditer(text):
            if _natid_ok(m.group(0)): add(m.start(), m.end(), m.group(0), "natid")

        # 9) dates
        for m in DATE_RE.finditer(text):
            found.append((m.start(), m.end(), m.group(0), "date", None, PRIO["date"], False))

        # 10) generic patterns, URLs, hostnames, config values
        for typ in ("email", "domain", "ipv6", "ipv4", "mac"):
            if not on(typ): continue
            for m in PAT[typ].finditer(text):
                v = m.group(0)
                if not v: continue
                if typ == "domain" and not _valid_domain(v): continue
                if typ == "email" and _benign_domain(v.split("@", 1)[1]): continue
                if typ in ("ipv4", "ipv6"):
                    if _benign_ip(v): continue
                    pm = re.match(r"/\d{1,3}", text[m.end():m.end() + 4])
                    if pm and (v + pm.group(0)) in WELL_KNOWN_NETS: continue
                if typ == "mac" and _benign_mac(v): continue
                add(m.start(), m.end(), v, typ)
        if on("url"):
            for m in URL_RE.finditer(text):
                v = re.sub(r"[.,;:!?]+$", "", m.group(0))
                if _url_kind(v, text) == "mask":
                    add(m.start(), m.start() + len(v), v, "url")
        protected = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
        if on("hostname"):
            seen = set()
            for m in KW_RE.finditer(text):
                name = m.group(1); s = m.start() + m.group(0).rfind(name)
                if (s, s + len(name)) not in seen and _host_label_ok(name):
                    seen.add((s, s + len(name)))
                    add(s, s + len(name), name, "hostname", prop=not re.search(r"\d", name))
            ends = {pe for _, pe in protected}
            for m in TOK_RE.finditer(text):
                t = m.group(0)
                if (m.start(), m.end()) in seen: continue
                if re.match(r"\.\d", text[m.end():m.end() + 2]): continue        # version: xxx-7.4.12
                if re.match(r"\"\s*:", text[m.end():m.end() + 3]): continue      # JSON key
                if re.fullmatch(r"[0-9a-fA-F]{1,4}", t) and text[m.end():m.end() + 1] == ":": continue
                if m.start() - 1 in ends and text[m.start() - 1] in "-_": continue  # PROJECT_1-web-1
                if _looks_like_host(t): add(m.start(), m.end(), t, "hostname")
        if on("config"):
            values = dict(conn_dbs)
            for rx in (CFG_FREE_RE, CFG_STRICT_RE):
                for m in rx.finditer(text):
                    val = re.sub(r"[:.]+$", "", m.group(2) or "")
                    if len(val) >= 2 and val.lower() not in CFG_STOP and not is_token(val):
                        values.setdefault(val, _cfg_prefix(m.group(1)))
            for m in CFG_ENV_RE.finditer(text):
                val = re.sub(r"[:.]+$", "", m.group("v"))
                if len(val) >= 2 and val.lower() not in CFG_STOP and not is_token(val):
                    values.setdefault(val, _cfg_prefix(m.group("key")))
            for v, p in values.items():
                for m in _bounded(v).finditer(text):
                    add(m.start(), m.end(), v, "config", p)

        # 11) spread learned names over the whole text (this message + earlier ones)
        spread = dict(learned)
        for f in found:
            if f[3] in ("domain", "url"):
                for lbl in _host_spread_labels(f[2], f[3]): spread.setdefault(lbl, ("hostname", None))
        for e in self.entries:
            if e.get("secret"): continue
            if e.get("prop"):
                spread.setdefault(e["real"], (e["type"], None))
            if e["type"] in ("domain", "url"):
                for lbl in _host_spread_labels(e["real"], e["type"]): spread.setdefault(lbl, ("hostname", None))
        for v, (typ, p) in spread.items():
            if len(v) < 4 or v.lower() in COMMON_WORDS or v.lower() in SYSTEM_USERS: continue
            if not on(typ) or v not in text: continue
            for m in _spread_re(v).finditer(text):
                add(m.start(), m.end(), v, typ, p, prio=P_SPREAD)

        found = [f for f in found if not any(f[0] < pe and ps < f[1] for ps, pe in protected)]
        secret_spans = [(f[0], f[1]) for f in found if f[3] == "secret"]
        found = [f for f in found if f[3] != "url" or not any(f[0] < se and ss < f[1] for ss, se in secret_spans)]

        found.sort(key=lambda x: (x[0], -x[5], -(x[1] - x[0])))
        chosen = []; last_end = -1
        for f in found:
            if f[0] >= last_end:
                chosen.append(f); last_end = f[1]
        if not opts.get("date"):
            chosen = [c for c in chosen if c[3] != "date"]
        return [(s, e, v, t, p, pr) for s, e, v, t, p, _, pr in chosen]

    # ---- public API ----
    def anonymize(self, text, opts=None):
        with self.lock:
            matches = self._collect(text, opts)
            out = []; i = 0
            for s, e, v, t, p, pr in matches:
                out.append(text[i:s]); out.append(self._get_fake(v, t, p, pr)); i = e
            out.append(text[i:])
            if matches: self.save()
            return "".join(out), len(matches)

    def classify(self, text, opts=None):
        """('restore'|'anon', known tokens, new sensitive values): restore only if known tokens dominate."""
        with self.lock:
            known = sum(1 for m in TOKEN_RE.finditer(text) if m.group(0) in self.tok)
            new = len(self._collect(text, opts))
        return ("restore" if known > 0 and known >= new else "anon"), known, new

    def legacy_count(self):
        """Entries with realistic fake values from the very first release."""
        return sum(1 for e in self.entries if not is_token(e["fake"]))

    @staticmethod
    def _guard(typ):
        if typ == "ipv4": return (r"(?<![0-9.])", r"(?![0-9.])")
        if typ in ("ipv6", "mac"): return (r"(?<![0-9A-Fa-f:.\-])", r"(?![0-9A-Fa-f:.\-])")
        return (r"(?<![A-Za-z0-9._\-\/])", r"(?![A-Za-z0-9._\-\/])")

    def restore(self, text, wrap=None):
        """Replace known tokens with real values. wrap(real) lets a UI mark what was restored."""
        w = wrap or (lambda r: r)
        with self.lock:
            count = [0]
            def sub(m):
                real = self.tok.get(m.group(0))
                if real is None: return m.group(0)
                count[0] += 1; return w(real)
            text = TOKEN_RE.sub(sub, text)
            for p in sorted((e for e in self.entries if not is_token(e["fake"])), key=lambda x: -len(x["fake"])):
                lb, la = self._guard(p["type"])
                text, n = re.subn(lb + re.escape(p["fake"]) + la, lambda _m, r=p["real"]: w(r), text)
                count[0] += n
            return text, count[0]

    def import_entries(self, items):
        """Merge an exported ledger; conflicting entries are skipped. Returns the number added."""
        added = 0
        with self.lock:
            for e in items:
                real, fake = e.get("real"), e.get("fake")
                if not real or not fake or e.get("secret") or real in self.real_to_fake or fake in self.tok:
                    continue
                ne = {"real": real, "fake": fake, "type": e.get("type", "custom")}
                if e.get("prop"): ne["prop"] = True
                self.real_to_fake[real] = fake; self.tok[fake] = real
                self.entries.append(ne); self.by_real[real] = ne
                if is_token(fake):
                    p, n = fake.rsplit("_", 1)
                    self.counters[p] = max(self.counters.get(p, 0), int(n))
                added += 1
            self.save()
        return added

    def export_entries(self):
        return [e for e in self.entries if not e.get("secret")]

    def export_data(self):
        """Ledger as stored on disk and in exports. Never contains secrets."""
        return {"version": 3, "entries": self.export_entries(), "counters": self.counters,
                "custom_terms": self.custom_terms}

    def set_custom(self, terms):
        with self.lock:
            self.custom_terms = terms; self.save()

    def save(self):
        if not self.store: return
        try:
            with open(self.store, "w", encoding="utf-8") as f:
                json.dump(dict(self.export_data(), settings=self.settings), f, ensure_ascii=False, indent=1)
        except Exception as ex:
            print("Save failed:", ex)

    def load(self):
        if not self.store or not os.path.exists(self.store): return
        try:
            with open(self.store, encoding="utf-8") as f: d = json.load(f)
            self.custom_terms = d.get("custom_terms", [])
            self.settings = d.get("settings", {}) or {}
            self.counters = {k: int(v) for k, v in d.get("counters", {}).items()}
            for e in d.get("entries", []):
                if e.get("secret") or not e.get("real") or not e.get("fake"): continue
                ne = {"real": e["real"], "fake": e["fake"], "type": e.get("type", "custom")}
                if e.get("prop"): ne["prop"] = True
                self.entries.append(ne)
                if e["real"] not in self.real_to_fake:
                    self.real_to_fake[e["real"]] = e["fake"]; self.by_real[e["real"]] = ne
                if is_token(e["fake"]):
                    self.tok[e["fake"]] = e["real"]
                    p, n = e["fake"].rsplit("_", 1)
                    self.counters[p] = max(self.counters.get(p, 0), int(n))
        except Exception as ex:
            print("Load failed:", ex)

    def clear(self):
        with self.lock:
            self._reset(); self.save()


# =====================================================================
#  I18N
# =====================================================================
STRINGS = {
    "en": {
        "types": {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "DNS", "url": "URL", "email": "Email", "mac": "MAC",
                  "hostname": "Host", "user": "User", "container": "Container", "project": "Project",
                  "iface": "Interface", "config": "Config", "secret": "Secret", "date": "Date", "custom": "Custom",
                  "natid": "National ID"},
        "tagline": "Masks logs and configs before they reach an AI assistant",
        "hotkeys": "Hotkeys", "mode": "Mode", "mode_smart": "Smart", "mode_mask": "Mask only",
        "mode_smart_on": "Mode: Smart — logs are masked, AI answers are restored",
        "mode_mask_on": "Mode: Mask only — every copy is masked",
        "auto": "Auto-watch", "auto_on": "Auto-watch on", "auto_off": "Auto-watch off",
        "ready": "Ready", "hero_on": "Protection active",
        "hero_on_smart": "Logs you copy are masked instantly; AI answers you copy come back with real values.",
        "hero_on_mask": "Everything you copy is masked. Restore manually on the Restore tab.",
        "hero_off": "Auto-watch is off",
        "hero_off_sub": "The clipboard is not watched. Paste into the boxes or turn the switch on.",
        "tab_mask": "Mask", "tab_restore": "Restore", "tab_ledger": "Ledger",
        "grp_net": "Network", "grp_id": "Identity & secrets",
        "in_title": "Input", "in_hint": "log, config, error output",
        "out_title": "Text for the AI", "out_hint": "masked",
        "btn_mask": "Mask", "btn_restore": "Restore", "btn_clear": "Clear", "btn_copy": "Copy", "btn_ok": "OK",
        "custom_ph": "Custom terms (company, project code…), comma separated",
        "need_input": "Paste some text into the input box first.",
        "masked_n": "{n} items masked — use Copy to take it.", "masked_n_1": "1 item masked — use Copy to take it.",
        "nothing_masked": "Nothing sensitive found.", "no_output": "Nothing to copy yet.",
        "copied_masked": "Masked text is on the clipboard — paste it into the AI.",
        "cleared": "Cleared.", "badge": "{n} masked",
        "reply_title": "AI answer", "reply_hint": "text with tokens such as IP_PRIV_1, HOST_1",
        "real_title": "Real values", "real_hint": "for your editor / terminal", "dont_send": "Don't send to AI",
        "need_reply": "Paste the AI's answer first.",
        "restored_n": "{n} values restored.", "restored_n_1": "1 value restored.",
        "no_known": "No known tokens in this text.", "copied_real": "Text with real values is on the clipboard.",
        "search_ph": "Search: IP, domain, token (HOST_3)…",
        "export": "Export", "import": "Import", "reset": "Reset",
        "exported": "Ledger exported (secrets excluded). It contains real values — don't share it.",
        "imported": "Ledger imported: {n} new entries.", "import_failed": "Could not read that file: {e}",
        "ledger_empty_already": "The ledger is already empty.",
        "reset_title": "Reset ledger",
        "reset_q": "Delete all mappings?\n\nAnswers to text you already sent to an AI can no longer be restored.",
        "reset_done": "Ledger reset.",
        "col_type": "TYPE", "col_real": "REAL", "col_token": "TOKEN",
        "empty_ledger": "No mappings yet.\nThey appear here when you copy or mask a log.",
        "rows": "{n} entries", "rows_q": "{k} / {n} entries", "ledger_badge": "{n} in ledger",
        "secret_shown": "••••••••  ({n} chars · memory only)",
        "cap_clip": "Clipboard", "cap_keys": "Hotkeys", "cap_tray": "Tray", "cap_recopy": "Re-copy",
        "keys_title": "Keyboard shortcuts",
        "key_mask": "Mask the clipboard", "key_restore": "Restore the clipboard",
        "key_auto": "Toggle auto-watch", "key_box": "Process the focused box", "key_quit": "Quit",
        "keys_note": "With auto-watch on you don't need hotkeys: copy a log and it is masked, "
                     "copy the AI's answer and it comes back with real values.",
        "keys_missing": "Global hotkeys are off: pynput is not installed (pip install pynput). ",
        "cap_restore": "↩  AI answer: {n} values restored · real text is on the clipboard",
        "cap_restore_0": "AI answer captured, nothing to restore",
        "cap_mask": "●  {n} items masked · paste with Ctrl+V",
        "cap_mask_0": "Clipboard captured, nothing new to mask",
        "tray_show": "Show", "tray_auto_on": "Auto-watch: on", "tray_auto_off": "Auto-watch: off",
        "tray_mode_smart": "Mode: Smart", "tray_mode_mask": "Mode: Mask only",
        "tray_mask": "Mask clipboard  (Ctrl+Alt+A)", "tray_restore": "Restore clipboard  (Ctrl+Alt+R)",
        "tray_reset": "Reset ledger…", "tray_keys": "Hotkeys…", "tray_quit": "Quit",
        "bg_win": "Running in the background — open it from the tray icon.",
        "bg_other": "Minimised, still watching. Press Ctrl+Q to quit.",
        "keys_failed": "Hotkeys could not start: {e}",
        "clip_failed": "Cannot read the clipboard ({e}). On Linux: sudo apt install xclip",
        "no_pyperclip": "pyperclip is not installed — pip install pyperclip pynput",
        "keys_off": "Hotkeys are off (pynput missing) — the switch still works",
        "ready_long": "Ready — copy a log and the masked version lands on your clipboard.",
        "legacy": "{n} ledger entries are from the first release — Reset the ledger once for clean tokens",
        "clip_empty": "The clipboard is empty.",
        "clip_masked": "Clipboard masked: {n} items", "clip_nothing": "Nothing to mask on the clipboard.",
        "clip_restored": "Clipboard restored: {n} values", "clip_no_tokens": "No known tokens on the clipboard.",
        "error": "Error: {e}", "notify_masked": "🛡 Masked: {n} items", "notify_restored": "↩ Restored: {n} values",
        "missing_ui": "The UI package is missing.\n\npip install customtkinter",
        "crash_title": "MaskBoard could not start", "crash_details": "Details: {p}",
    },
    "tr": {
        "types": {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "DNS", "url": "URL", "email": "E-posta", "mac": "MAC",
                  "hostname": "Host", "user": "Kullanıcı", "container": "Konteyner", "project": "Proje",
                  "iface": "Arayüz", "config": "Config", "secret": "Parola", "date": "Tarih", "custom": "Özel",
                  "natid": "T.C. kimlik"},
        "tagline": "Log ve config verilerini AI'a göndermeden önce maskeler",
        "hotkeys": "Kısayollar", "mode": "Yön", "mode_smart": "Akıllı", "mode_mask": "Sadece maskele",
        "mode_smart_on": "Yön: Akıllı — log maskelenir, AI cevabı geri çevrilir",
        "mode_mask_on": "Yön: Sadece maskele — her kopya maskelenir",
        "auto": "Oto-izle", "auto_on": "Oto-izle açık", "auto_off": "Oto-izle kapalı",
        "ready": "Hazır", "hero_on": "Koruma aktif",
        "hero_on_smart": "Kopyaladığın loglar anında maskelenir, AI cevapları gerçek değerlere döner.",
        "hero_on_mask": "Kopyaladığın her metin maskelenir. Geri çevirmeyi Geri Çevir sekmesinden yaparsın.",
        "hero_off": "Oto-izle kapalı",
        "hero_off_sub": "Pano izlenmiyor. Kutulara yapıştırarak çalışabilir ya da anahtarı açabilirsin.",
        "tab_mask": "Anonimleştir", "tab_restore": "Geri Çevir", "tab_ledger": "Defter",
        "grp_net": "Ağ", "grp_id": "Kimlik ve gizli",
        "in_title": "Giriş", "in_hint": "log, config, hata çıktısı",
        "out_title": "AI'a gidecek metin", "out_hint": "maskeli",
        "btn_mask": "Anonimleştir", "btn_restore": "Geri çevir", "btn_clear": "Temizle", "btn_copy": "Kopyala",
        "btn_ok": "Tamam",
        "custom_ph": "Özel terimler (firma adı, proje kodu…), virgülle",
        "need_input": "Önce giriş kutusuna bir metin yapıştır.",
        "masked_n": "{n} öğe maskelendi — Kopyala ile al.",
        "nothing_masked": "Maskelenecek bir değer bulunamadı.", "no_output": "Kopyalanacak çıktı yok.",
        "copied_masked": "Maskeli metin panoda — AI'a yapıştırabilirsin.",
        "cleared": "Temizlendi.", "badge": "{n} öğe maskelendi",
        "reply_title": "AI cevabı", "reply_hint": "IP_PRIV_1, HOST_1 gibi etiketler içeren metin",
        "real_title": "Gerçek değerler", "real_hint": "editörüne / terminaline", "dont_send": "AI'a gönderme",
        "need_reply": "Önce AI'ın cevabını yapıştır.",
        "restored_n": "{n} değer geri çevrildi.",
        "no_known": "Bu metinde defterdeki etiketlerden biri yok.", "copied_real": "Gerçek değerli metin panoda.",
        "search_ph": "Ara: IP, alan adı, etiket (HOST_3)…",
        "export": "Dışa aktar", "import": "İçe aktar", "reset": "Sıfırla",
        "exported": "Defter dışa aktarıldı (parolalar hariç). Gerçek değerler içerir — paylaşma.",
        "imported": "Defter içe aktarıldı: {n} yeni eşleşme.", "import_failed": "Dosya okunamadı: {e}",
        "ledger_empty_already": "Defter zaten boş.",
        "reset_title": "Defteri sıfırla",
        "reset_q": "Tüm eşleşmeler silinsin mi?\n\nDaha önce AI'a gönderdiğin metinlerin cevapları artık geri çevrilemez.",
        "reset_done": "Defter sıfırlandı.",
        "col_type": "TÜR", "col_real": "GERÇEK", "col_token": "ETİKET",
        "empty_ledger": "Henüz eşleşme yok.\nBir log kopyaladığında ya da anonimleştirdiğinde burada görünür.",
        "rows": "{n} kayıt", "rows_q": "{k} / {n} kayıt", "ledger_badge": "Defterde {n} eşleşme",
        "secret_shown": "••••••••  ({n} karakter · yalnızca bellekte)",
        "cap_clip": "Pano", "cap_keys": "Kısayol", "cap_tray": "Tepsi", "cap_recopy": "Tekrar-kopya",
        "keys_title": "Klavye kısayolları",
        "key_mask": "Panodaki metni anonimleştir", "key_restore": "Panodaki metni geri çevir",
        "key_auto": "Oto-izlemeyi aç / kapat", "key_box": "Kutudaki metni işle", "key_quit": "Uygulamadan çık",
        "keys_note": "Oto-izle açıkken kısayola gerek yok: log kopyala → maskelenir, "
                     "AI cevabını kopyala → gerçek değerlere döner.",
        "keys_missing": "Global kısayollar kapalı: pynput paketi yok (pip install pynput). ",
        "cap_restore": "↩  AI cevabı: {n} değer geri çevrildi · gerçek hali panoda",
        "cap_restore_0": "AI cevabı yakalandı, geri çevrilecek değer yoktu",
        "cap_mask": "●  {n} öğe maskelendi · Ctrl+V ile yapıştır",
        "cap_mask_0": "Pano yakalandı, maskelenecek yeni değer yoktu",
        "tray_show": "Göster", "tray_auto_on": "Oto-izle: açık", "tray_auto_off": "Oto-izle: kapalı",
        "tray_mode_smart": "Yön: Akıllı", "tray_mode_mask": "Yön: Sadece maskele",
        "tray_mask": "Panoyu anonimleştir  (Ctrl+Alt+A)", "tray_restore": "Panoyu geri çevir  (Ctrl+Alt+R)",
        "tray_reset": "Defteri sıfırla…", "tray_keys": "Kısayollar…", "tray_quit": "Çıkış",
        "bg_win": "Arka planda çalışıyor — tepsi simgesinden açabilirsin.",
        "bg_other": "Küçültüldü, izleme sürüyor. Çıkmak için Ctrl+Q.",
        "keys_failed": "Kısayollar başlatılamadı: {e}",
        "clip_failed": "Pano okunamıyor ({e}). Linux'ta: sudo apt install xclip",
        "no_pyperclip": "pyperclip yok — pip install pyperclip pynput ile kur.",
        "keys_off": "Kısayollar kapalı (pynput yok) — anahtar yine çalışır",
        "ready_long": "Hazır — bir log kopyala, maskeli hali panoya gelsin.",
        "legacy": "Defterde ilk sürümden {n} kayıt var — temiz etiketler için defteri bir kez sıfırla",
        "clip_empty": "Pano boş.",
        "clip_masked": "Panoda anonimleştirildi: {n} öğe", "clip_nothing": "Panoda maskelenecek bir şey yok.",
        "clip_restored": "Panoda geri çevrildi: {n} değer", "clip_no_tokens": "Panoda defterdeki etiketlerden biri yok.",
        "error": "Hata: {e}", "notify_masked": "🛡 Maskelendi: {n} öğe", "notify_restored": "↩ Geri çevrildi: {n} değer",
        "missing_ui": "Arayüz paketi eksik.\n\npip install customtkinter",
        "crash_title": "MaskBoard açılamadı", "crash_details": "Ayrıntılar: {p}",
    },
}
LANGS = ("en", "tr")
_lang = ["en"]

def detect_lang():
    """'tr' when the OS/user language is Turkish, otherwise 'en'."""
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        v = os.environ.get(var)
        if v and v not in ("C", "POSIX") and not v.startswith("C."):
            return "tr" if v.lower().startswith("tr") else "en"
    if sys.platform == "win32":
        try:
            import ctypes
            return "tr" if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x1F else "en"
        except Exception:
            pass
    try:
        loc = locale.getlocale()[0] or ""
    except Exception:
        loc = ""
    return "tr" if loc.lower().startswith("tr") else "en"

def set_lang(code): _lang[0] = code if code in STRINGS else "en"

def T(key, **kw):
    table = STRINGS[_lang[0]]
    if kw.get("n") == 1 and key + "_1" in table:
        key += "_1"
    s = table.get(key, STRINGS["en"].get(key, key))
    return s.format(**kw) if kw else s

def type_label(typ): return STRINGS[_lang[0]]["types"].get(typ, typ)


# =====================================================================
#  CLIPBOARD AGENT
# =====================================================================
def _norm(s):
    """Normalise clipboard text for comparisons (CRLF, trailing NUL/whitespace)."""
    return (s or "").replace("\r\n", "\n").replace("\r", "\n").rstrip("\x00").strip()


def _clipboard_counter():
    """OS counter that ticks on every copy, even of identical text (Windows, macOS, X11)."""
    if sys.platform == "win32":
        try:
            import ctypes
            fn = ctypes.windll.user32.GetClipboardSequenceNumber
            fn.restype = ctypes.c_uint32
            fn()
            return lambda: int(fn())
        except Exception:
            return None
    if sys.platform == "darwin":
        try:
            from AppKit import NSPasteboard
            pb = NSPasteboard.generalPasteboard()
            return lambda: int(pb.changeCount())
        except Exception:
            return None
    return _x11_counter()


def _x11_counter():
    """Count CLIPBOARD owner changes via XFixes (python-xlib ships with pynput)."""
    if not os.environ.get("DISPLAY"):
        return None
    try:
        import Xlib.display
        from Xlib.ext import xfixes
        disp = Xlib.display.Display()
        if not disp.has_extension("XFIXES"):
            return None
        disp.xfixes_query_version()
        clip = disp.intern_atom("CLIPBOARD")
        disp.xfixes_select_selection_input(disp.screen().root, clip, xfixes.XFixesSetSelectionOwnerNotifyMask)
        disp.flush()
    except Exception:
        return None
    state = {"n": 0}
    def listen():
        while True:
            try:
                ev = disp.next_event()
                if (ev.type, getattr(ev, "sub_code", None)) == disp.extension_event.SetSelectionOwnerNotify:
                    state["n"] += 1
            except Exception:
                return
    threading.Thread(target=listen, daemon=True).start()
    return lambda: state["n"]

ECHO_GRACE = 1.0   # seconds: our own write reappearing this soon (RDP sync) is an echo, not a copy


class Agent:
    def __init__(self, counter="auto", mapper=None):
        self.mapper = mapper or Mapper()
        self.auto = False
        self.mode = "smart"               # smart: log → mask, AI answer → restore · mask: always mask
        self.counter = _clipboard_counter() if counter == "auto" else counter
        self.last_seq = None
        self.seen_norm = None             # last clipboard content we saw
        self.written_norm = None          # last clipboard content we wrote
        self.written_at = 0.0
        self.running = True
        self.gui = None
        self.get_opts = lambda: None
        self.notify = lambda title, msg: None

    def _seq(self):
        if not self.counter: return None
        try: return self.counter()
        except Exception: return None

    def sync_now(self):
        """Treat the current clipboard as already seen."""
        self.last_seq = self._seq()
        try: self.seen_norm = _norm(pyperclip.paste()) if pyperclip else None
        except Exception: pass

    def mark_written(self, text):
        """Call after the app itself wrote to the clipboard, so it is not taken for a user copy."""
        self.written_norm = _norm(text); self.seen_norm = self.written_norm
        self.written_at = time.time()
        self.last_seq = self._seq()

    def _write(self, text):
        pyperclip.copy(text); self.mark_written(text)

    def _clip_apply(self, fn, done_key, none_key):
        if not pyperclip: return self._flash(T("no_pyperclip"))
        txt = pyperclip.paste()
        if not txt.strip(): return self._flash(T("clip_empty"))
        out, n = fn(txt)
        if out == txt: return self._flash(T(none_key))
        self._write(out); self._flash(T(done_key, n=n)); self._refresh()

    def clip_anonymize(self):
        self._clip_apply(lambda t: self.mapper.anonymize(t, self.get_opts()), "clip_masked", "clip_nothing")

    def clip_restore(self):
        self._clip_apply(self.mapper.restore, "clip_restored", "clip_no_tokens")

    def handle_copy(self, cur):
        """Process a new copy. Returns (kind, output, count)."""
        opts = self.get_opts()
        kind = self.mapper.classify(cur, opts)[0] if self.mode == "smart" else "anon"
        out, n = self.mapper.restore(cur) if kind == "restore" else self.mapper.anonymize(cur, opts)
        return kind, out, n

    def _poll(self):
        """Clipboard text if there was a new copy since the last poll, else None."""
        seq = self._seq()
        if seq is not None and sys.platform.startswith("linux"):
            # X11 counter plus a content check (the counter can miss events under Wayland)
            seq_changed = seq != self.last_seq
            self.last_seq = seq
            try: cur = pyperclip.paste()
            except Exception: return None
            ncur = _norm(cur)
            if not seq_changed and ncur == self.seen_norm: return None
            self.seen_norm = ncur
            if ncur == self.written_norm:
                if not seq_changed or time.time() - self.written_at < ECHO_GRACE: return None
            return cur
        if seq is not None:
            if seq == self.last_seq: return None
            self.last_seq = seq
            try: cur = pyperclip.paste()
            except Exception: return None
            ncur = _norm(cur)
            if ncur == self.written_norm and time.time() - self.written_at < ECHO_GRACE:
                return None
            self.seen_norm = ncur
            return cur
        # No counter: only content changes are visible, re-copying identical text is not.
        try: cur = pyperclip.paste()
        except Exception: return None
        ncur = _norm(cur)
        if ncur == self.seen_norm: return None
        self.seen_norm = ncur
        return None if ncur == self.written_norm else cur

    def watch_loop(self):
        while self.running:
            if pyperclip:
                cur = self._poll()
                if cur is not None and self.auto and _norm(cur):
                    try:
                        kind, out, n = self.handle_copy(cur)
                    except Exception as ex:
                        self._flash(T("error", e=ex)); time.sleep(0.3); continue
                    if out != cur:
                        self._write(out)
                        self.notify(APP_NAME, T("notify_restored" if kind == "restore" else "notify_masked", n=n))
                    if self.gui: self.gui.capture(kind, cur, out, n)
                    self._refresh()
            time.sleep(0.25)

    def _flash(self, msg):
        print("•", msg)
        if self.gui: self.gui.flash(msg)

    def _refresh(self):
        if self.gui: self.gui.refresh()

    def stop(self): self.running = False


# =====================================================================
#  ICON — shield with redaction bars
# =====================================================================
try:
    from PIL import Image as PILImage, ImageDraw as PILDraw, ImageFilter as PILFilter, ImageChops as PILChops
except Exception:
    PILImage = None

def _bezier(p0, p1, p2, p3, n=48):
    pts = []
    for i in range(n + 1):
        t = i / n; u = 1 - t
        pts.append((u**3*p0[0] + 3*u*u*t*p1[0] + 3*u*t*t*p2[0] + t**3*p3[0],
                    u**3*p0[1] + 3*u*u*t*p1[1] + 3*u*t*t*p2[1] + t**3*p3[1]))
    return pts

def _shield(cx, top, w, h):
    L, R, T_ = cx - w/2, cx + w/2, top
    r = w * 0.13
    pts = []
    pts += _bezier((L, T_ + r), (L, T_), (L, T_), (L + r, T_), 12)
    pts += _bezier((R - r, T_), (R, T_), (R, T_), (R, T_ + r), 12)
    pts += _bezier((R, T_ + h*0.46), (R, T_ + h*0.80), (cx + w*0.20, T_ + h*0.93), (cx, T_ + h))
    pts += _bezier((cx, T_ + h), (cx - w*0.20, T_ + h*0.93), (L, T_ + h*0.80), (L, T_ + h*0.46))
    return pts

_ICON_CACHE = {}
def app_icon(size=256):
    """App icon (RGBA), drawn supersampled on a 1024 grid."""
    if size in _ICON_CACHE: return _ICON_CACHE[size]
    S = 2048 if size > 64 else 1024
    k = S / 1024
    v = PILImage.linear_gradient("L").resize((S, S))
    grad = PILChops.add(v, v.rotate(90), scale=2.0)
    tile = PILImage.composite(PILImage.new("RGBA", (S, S), (24, 74, 168, 255)),
                              PILImage.new("RGBA", (S, S), (43, 212, 168, 255)), grad)
    mask = PILImage.new("L", (S, S), 0)
    PILDraw.Draw(mask).rounded_rectangle([int(40*k), int(40*k), int(984*k), int(984*k)], radius=int(220*k), fill=255)
    img = PILImage.new("RGBA", (S, S), (0, 0, 0, 0)); img.paste(tile, (0, 0), mask)
    shadow = PILImage.new("L", (S, S), 0)
    PILDraw.Draw(shadow).polygon([(x*k, (y+26)*k) for x, y in _shield(512, 210, 560, 640)], fill=110)
    shadow = PILChops.multiply(shadow.filter(PILFilter.GaussianBlur(28*k)), mask)
    img = PILImage.composite(PILImage.new("RGBA", (S, S), (6, 20, 40, 255)), img, shadow)
    d = PILDraw.Draw(img)
    d.polygon([(x*k, y*k) for x, y in _shield(512, 210, 560, 640)], fill=(244, 252, 250, 255))
    for x0, y0, x1, col in ((338, 360, 686, (14, 42, 59, 255)),
                            (338, 470, 600, (43, 212, 168, 255)),
                            (338, 580, 650, (14, 42, 59, 255))):
        d.rounded_rectangle([x0*k, y0*k, x1*k, (y0+64)*k], radius=int(32*k), fill=col)
    out = img.resize((size, size), PILImage.LANCZOS)
    _ICON_CACHE[size] = out
    return out

def export_icon(path):
    """Write the icon as .ico (every size drawn separately) or .png (512 px)."""
    if PILImage is None:
        raise SystemExit("Pillow is required for the icon: pip install Pillow")
    if path.lower().endswith(".ico"):
        sizes = (16, 24, 32, 48, 64, 128, 256)
        frames = [app_icon(s) for s in sizes]
        frames[-1].save(path, format="ICO", sizes=[(s, s) for s in sizes], append_images=frames[:-1])
    else:
        app_icon(512).save(path)
    return path


# =====================================================================
#  GUI
# =====================================================================
def run_gui(agent):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, font as tkfont
    try:
        import customtkinter as ctk
    except ImportError:
        try:
            r = tk.Tk(); r.withdraw(); messagebox.showerror(APP_NAME, T("missing_ui"))
        except Exception:
            pass
        raise SystemExit("customtkinter is missing: pip install customtkinter")

    if sys.platform == "win32":
        try:   # our icon instead of Python's in the taskbar when run as a script
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("MaskBoard.App")
        except Exception:
            pass

    ctk.set_appearance_mode("dark")
    BG, SURF, SURF2, INK = "#0B0E14", "#121722", "#182030", "#0D121A"
    BORDER, BORDER2 = "#232C3B", "#33405A"
    TEXT, MUTED, FAINT = "#E8EDF5", "#8C97AB", "#5D687C"
    TEAL, TEAL_H, TEAL_INK, TEAL_BG, TEAL_LINE = "#2BD4A8", "#55E3C0", "#04261E", "#10302A", "#1F5F50"
    CORAL, CORAL_BG, CORAL_LINE = "#FF8A7A", "#3A1F1D", "#5A2E2A"
    SEL, SEL_H = "#26324A", "#2C3A55"

    root = ctk.CTk(fg_color=BG)
    root.title(APP_NAME)
    try:
        sc = ctk.ScalingTracker.get_window_scaling(root)
        max_h = int(root.winfo_screenheight() / sc) - 90
    except Exception:
        sc, max_h = 1.0, 820
    root.geometry("1000x%d" % min(800, max_h)); root.minsize(860, min(640, max_h))

    fams = set(tkfont.families(root))
    def pick(*names): return next((n for n in names if n in fams), None)
    UI = pick("Segoe UI Variable Text", "Segoe UI", "Inter", "SF Pro Text", "Helvetica Neue",
              "Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans") or "TkDefaultFont"
    UI_D = pick("Segoe UI Variable Display", "Segoe UI Semibold", "Segoe UI", "Inter", "SF Pro Display",
                "Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans") or UI
    MONO = pick("Cascadia Mono", "Cascadia Code", "JetBrains Mono", "SF Mono", "Consolas",
                "Ubuntu Mono", "DejaVu Sans Mono") or "TkFixedFont"
    def F(size, weight="normal", family=None): return ctk.CTkFont(family=family or UI, size=size, weight=weight)

    ico_path = None
    if PILImage is not None:
        try:
            if sys.platform == "win32":
                import tempfile
                ico_path = export_icon(os.path.join(tempfile.gettempdir(), "maskboard.ico"))
                root.iconbitmap(ico_path)
            else:
                from PIL import ImageTk
                root._icon_ref = ImageTk.PhotoImage(app_icon(256))
                root.iconphoto(True, root._icon_ref)
        except Exception:
            pass

    # ---- translation registry: every static text re-applies itself on a language switch ----
    retranslate = []
    def tx(widget, key, attr="text", fmt="%s"):
        def apply(): widget.configure(**{attr: fmt % T(key)})
        retranslate.append(apply); apply()
        return widget

    def put_clipboard(t):
        if pyperclip:
            agent._write(t)
        else:
            root.clipboard_clear(); root.clipboard_append(t); root.update(); agent.mark_written(t)

    def card(master):
        return ctk.CTkFrame(master, fg_color=SURF, corner_radius=14, border_width=1, border_color=BORDER)

    def clear(master):
        return ctk.CTkFrame(master, fg_color="transparent")

    BTN = {
        "primary":   dict(fg_color=TEAL, hover_color=TEAL_H, text_color=TEAL_INK, border_width=0),
        "secondary": dict(fg_color=SURF2, hover_color="#212B3D", text_color=TEXT, border_width=1, border_color=BORDER),
        "ghost":     dict(fg_color="transparent", hover_color=SURF2, text_color=MUTED, border_width=0),
        "outline":   dict(fg_color="transparent", hover_color=TEAL_BG, text_color=TEAL, border_width=1, border_color=TEAL_LINE),
        "danger":    dict(fg_color="transparent", hover_color=CORAL_BG, text_color=CORAL, border_width=1, border_color=CORAL_LINE),
    }
    def btn(master, key, cmd, kind="secondary", width=110, height=34, size=12):
        b = ctk.CTkButton(master, text="", command=cmd, width=width, height=height, corner_radius=9,
                          font=F(size if kind != "primary" else size + 1, "bold"), **BTN[kind])
        return tx(b, key)

    def segmented(master, values, command, height):
        return ctk.CTkSegmentedButton(master, values=values, command=command, height=height,
                                      font=F(12 if height < 36 else 13, "bold"), fg_color=SURF,
                                      selected_color=SEL, selected_hover_color=SEL_H, unselected_color=SURF,
                                      unselected_hover_color=SURF2, text_color=TEXT, corner_radius=9)

    def textbox(master):
        t = ctk.CTkTextbox(master, height=90, fg_color=INK, border_width=1, border_color=BORDER, corner_radius=10,
                           text_color=TEXT, font=ctk.CTkFont(family=MONO, size=12), wrap="word",
                           border_spacing=10, scrollbar_button_color=BORDER, scrollbar_button_hover_color=BORDER2)
        t.bind("<FocusIn>", lambda e: t.configure(border_color=TEAL_LINE), add=True)
        t.bind("<FocusOut>", lambda e: t.configure(border_color=BORDER), add=True)
        return t

    def set_text(tb, s):
        tb.delete("1.0", "end"); tb.insert("1.0", s)

    def show_fakes(tb, text):
        set_text(tb, text)
        for m in TOKEN_RE.finditer(text):
            tb.tag_add("fake", "1.0+%dc" % m.start(), "1.0+%dc" % m.end())

    def show_restored(tb, text):
        """Restore with markers, then highlight exactly the restored spans."""
        marked, n = agent.mapper.restore(text, wrap=lambda r: "\x00" + r + "\x01")
        plain, spans, pos = [], [], 0
        for part in re.split(r"(\x00[\s\S]*?\x01)", marked):
            if part.startswith("\x00"):
                part = part[1:-1]; spans.append((pos, pos + len(part)))
            plain.append(part); pos += len(part)
        set_text(tb, "".join(plain))
        for s, e in spans:
            tb.tag_add("real", "1.0+%dc" % s, "1.0+%dc" % e)
        return "".join(plain), n

    def show_hotkeys(*_):
        win = ctk.CTkToplevel(root, fg_color=BG)
        win.title(T("hotkeys")); win.resizable(False, False); win.transient(root)
        if ico_path:
            win.after(250, lambda: win.iconbitmap(ico_path))
        body = clear(win); body.pack(fill="both", expand=True, padx=26, pady=24)
        ctk.CTkLabel(body, text=T("keys_title"), font=F(17, "bold", UI_D), text_color=TEXT,
                     anchor="w").pack(anchor="w", pady=(0, 14))
        rows = [(("Ctrl", "Alt", "A"), "key_mask"), (("Ctrl", "Alt", "R"), "key_restore"),
                (("Ctrl", "Alt", "T"), "key_auto"), (("Ctrl", "Enter"), "key_box"), (("Ctrl", "Q"), "key_quit")]
        grid = clear(body); grid.pack(fill="x")
        for row, (keys, desc) in enumerate(rows):
            kf = clear(grid); kf.grid(row=row, column=0, sticky="w", pady=4)
            for i, kname in enumerate(keys):
                if i: ctk.CTkLabel(kf, text="+", text_color=FAINT, font=F(11), width=14).pack(side="left")
                ctk.CTkLabel(kf, text=" %s " % kname, font=F(11, "bold"), text_color=TEXT, fg_color=SURF2,
                             corner_radius=6, height=26).pack(side="left")
            ctk.CTkLabel(grid, text=T(desc), font=F(13), text_color=MUTED, anchor="w").grid(
                row=row, column=1, sticky="w", padx=(18, 0))
        note = (T("keys_missing") if not keyboard else "") + T("keys_note")
        ctk.CTkLabel(body, text=note, font=F(12), text_color=(CORAL if not keyboard else FAINT),
                     wraplength=400, justify="left", anchor="w").pack(anchor="w", pady=(16, 18))
        ctk.CTkButton(body, text=T("btn_ok"), command=win.destroy, width=120, height=36, corner_radius=9,
                      font=F(13, "bold"), **BTN["primary"]).pack(anchor="e")
        win.update_idletasks()
        x = root.winfo_rootx() + (root.winfo_width() - win.winfo_reqwidth()) // 2
        y = root.winfo_rooty() + (root.winfo_height() - win.winfo_reqheight()) // 3
        win.geometry("+%d+%d" % (max(x, 0), max(y, 0)))
        win.lift(); win.focus_force()

    # ---------- header ----------
    header = clear(root); header.pack(fill="x", padx=26, pady=(22, 14))
    if PILImage is not None:
        try:
            logo = ctk.CTkImage(light_image=app_icon(128), dark_image=app_icon(128), size=(42, 42))
            ctk.CTkLabel(header, text="", image=logo).pack(side="left")
        except Exception as ex:
            print("Logo unavailable:", ex)
    title_box = clear(header); title_box.pack(side="left", padx=(12, 0))
    ctk.CTkLabel(title_box, text=APP_NAME, font=F(21, "bold", UI_D), text_color=TEXT, anchor="w").pack(anchor="w")
    tx(ctk.CTkLabel(title_box, font=F(12), text_color=MUTED, anchor="w"), "tagline").pack(anchor="w")

    def on_lang(code):
        set_lang(code.lower())
        agent.mapper.settings["lang"] = _lang[0]; agent.mapper.save()
        apply_lang()
    lang_seg = segmented(header, ["EN", "TR"], on_lang, 32)
    lang_seg.set(_lang[0].upper()); lang_seg.pack(side="right", padx=(10, 0))
    btn(header, "hotkeys", show_hotkeys, "ghost", width=96, height=32).pack(side="right", padx=(10, 0))

    MODE_KEYS = {"smart": "mode_smart", "mask": "mode_mask"}
    def on_mode(label):
        agent.mode = next((m for m, k in MODE_KEYS.items() if T(k) == label), "smart"); gui.refresh()
        gui.flash(T("mode_smart_on" if agent.mode == "smart" else "mode_mask_on"))
    mode_seg = segmented(header, [T(k) for k in MODE_KEYS.values()], on_mode, 32)
    mode_seg.pack(side="right")
    tx(ctk.CTkLabel(header, font=F(12), text_color=FAINT), "mode").pack(side="right", padx=(0, 10))
    def toggle_mode():
        agent.mode = "mask" if agent.mode == "smart" else "smart"
        mode_seg.set(T(MODE_KEYS[agent.mode])); on_mode(mode_seg.get())

    # ---------- status card ----------
    hero = card(root); hero.pack(fill="x", padx=26)
    top = clear(hero); top.pack(fill="x", padx=20, pady=(16, 0))
    dot = ctk.CTkLabel(top, text="●", font=F(20), text_color=TEAL, width=22); dot.pack(side="left", anchor="n")
    tbox = clear(top); tbox.pack(side="left", padx=(8, 0), fill="x", expand=True)
    hero_title = ctk.CTkLabel(tbox, text="", font=F(16, "bold", UI_D), text_color=TEXT, anchor="w")
    hero_title.pack(anchor="w")
    hero_sub = ctk.CTkLabel(tbox, text="", font=F(12), text_color=MUTED, anchor="w", justify="left")
    hero_sub.pack(anchor="w", fill="x")

    auto_var = tk.BooleanVar(value=False)
    def set_auto(value, quiet=False):
        agent.auto = bool(value)
        def _():
            if auto_var.get() != agent.auto: auto_var.set(agent.auto)
            gui.refresh()
            if not quiet: gui.flash(T("auto_on" if agent.auto else "auto_off"))
        root.after(0, _)
    auto_sw = ctk.CTkSwitch(top, variable=auto_var, onvalue=True, offvalue=False,
                            command=lambda: set_auto(auto_var.get()), switch_width=54, switch_height=28,
                            progress_color=TEAL, fg_color=BORDER2, button_color="#F2F6FB",
                            button_hover_color="#FFFFFF", font=F(13, "bold"), text_color=TEXT)
    tx(auto_sw, "auto").pack(side="right")

    ctk.CTkFrame(hero, height=1, fg_color=BORDER).pack(fill="x", padx=20, pady=(14, 0))
    hb = clear(hero); hb.pack(fill="x", padx=20, pady=(10, 14))
    caps_box = clear(hb); caps_box.pack(side="right")
    last_lbl = tx(ctk.CTkLabel(hb, font=F(12), text_color=MUTED, anchor="w"), "ready")
    last_lbl.pack(side="left", fill="x", expand=True)
    caps = []
    def draw_caps():
        for w in caps_box.winfo_children(): w.destroy()
        for key, ok in caps:
            ctk.CTkLabel(caps_box, text=("  ✓  %s  " if ok else "  ✕  %s  ") % T(key), height=24, corner_radius=12,
                         font=F(11, "bold"), fg_color=(TEAL_BG if ok else SURF2),
                         text_color=(TEAL if ok else FAINT)).pack(side="left", padx=(6, 0))

    # ---------- tabs ----------
    tabbar = clear(root); tabbar.pack(fill="x", padx=26, pady=(18, 12))
    PAGES = ["tab_mask", "tab_restore", "tab_ledger"]
    current = [PAGES[0]]
    tabs = segmented(tabbar, [T(k) for k in PAGES], lambda label: show_page(
        next((k for k in PAGES if T(k) == label), PAGES[0])), 38)
    tabs.pack(side="left")
    ledger_badge = ctk.CTkLabel(tabbar, text="", font=F(12), text_color=FAINT)
    ledger_badge.pack(side="left", padx=(12, 0))

    content = clear(root); content.pack(fill="both", expand=True, padx=26, pady=(0, 22))
    content.grid_rowconfigure(0, weight=1); content.grid_columnconfigure(0, weight=1)
    pages = {}
    for key in PAGES:
        f = clear(content); f.grid(row=0, column=0, sticky="nsew"); pages[key] = f
    def show_page(key):
        current[0] = key; pages[key].tkraise()
        if tabs.get() != T(key): tabs.set(T(key))

    def io_card(master, title_key, hint_key):
        c = card(master)
        h = clear(c); h.pack(fill="x", padx=16, pady=(12, 8))
        tx(ctk.CTkLabel(h, font=F(12, "bold"), text_color=TEXT, anchor="w"), title_key).pack(side="left")
        tx(ctk.CTkLabel(h, font=F(12), text_color=FAINT, anchor="w"), hint_key, fmt="  ·  %s").pack(side="left")
        t = textbox(c); t.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        return c, h, t

    # ===== Mask =====
    pa = pages["tab_mask"]
    pa.grid_columnconfigure(0, weight=1)
    pa.grid_rowconfigure(1, weight=1, uniform="io"); pa.grid_rowconfigure(3, weight=1, uniform="io")
    chiprow = clear(pa); chiprow.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    CHIP_GROUPS = [("grp_net", ("ipv4", "ipv6", "domain", "url", "hostname", "mac", "iface")),
                   ("grp_id", ("user", "email", "natid", "container", "config", "secret", "date", "custom"))]
    optvars = {}
    def make_chip(parent, t):
        v = tk.BooleanVar(value=t not in DEFAULT_OFF); optvars[t] = v
        b = ctk.CTkButton(parent, text=type_label(t), width=10, height=30, corner_radius=15, font=F(11, "bold"),
                          border_width=1)
        def paint():
            on = v.get()
            b.configure(fg_color=(TEAL_BG if on else "transparent"), hover_color=(TEAL_LINE if on else SURF2),
                        border_color=(TEAL_LINE if on else BORDER), text_color=(TEAL if on else FAINT))
        b.configure(command=lambda: (v.set(not v.get()), paint()))
        retranslate.append(lambda: b.configure(text=type_label(t)))
        paint(); return b
    for gi, (gkey, types_) in enumerate(CHIP_GROUPS):
        row = clear(chiprow); row.pack(fill="x", pady=(0 if gi == 0 else 6, 0))
        tx(ctk.CTkLabel(row, font=F(11), text_color=FAINT, width=120, anchor="w"), gkey).pack(side="left")
        for t in types_:
            make_chip(row, t).pack(side="left", padx=(0, 6))
    def get_opts(): return {t: optvars[t].get() for t in ALL_TYPES}
    agent.get_opts = get_opts

    in_card, in_head, src = io_card(pa, "in_title", "in_hint")
    in_card.grid(row=1, column=0, sticky="nsew")
    out_badge = ctk.CTkLabel(in_head, text="", font=F(11, "bold"), height=22, corner_radius=11,
                             fg_color=TEAL_BG, text_color=TEAL)
    badge_n = [None]
    def set_badge(n):
        badge_n[0] = n
        if n is None: return out_badge.pack_forget()
        out_badge.configure(text="  %s  " % T("badge", n=n)); out_badge.pack(side="right")
    retranslate.append(lambda: set_badge(badge_n[0]))

    act1 = clear(pa); act1.grid(row=2, column=0, sticky="ew", pady=12)
    def do_anon():
        agent.mapper.set_custom([s.strip() for s in custom_entry.get().split(",") if s.strip()])
        txt = src.get("1.0", "end-1c")
        if not txt.strip(): return gui.flash(T("need_input"))
        masked, n = agent.mapper.anonymize(txt, get_opts())
        show_fakes(masked_out, masked); gui.refresh(); set_badge(n)
        gui.flash(T("masked_n", n=n) if n else T("nothing_masked"), "ok" if n else "info")
    def copy_masked():
        t = masked_out.get("1.0", "end-1c")
        if not t.strip(): return gui.flash(T("no_output"))
        put_clipboard(t); gui.flash(T("copied_masked"), "ok")
    def clear_in():
        src.delete("1.0", "end"); masked_out.delete("1.0", "end"); set_badge(None); gui.flash(T("cleared"))
    btn(act1, "btn_mask", do_anon, "primary", width=170, height=42).pack(side="left")
    ctk.CTkLabel(act1, text="Ctrl+Enter", font=F(11), text_color=FAINT).pack(side="left", padx=12)
    btn(act1, "btn_clear", clear_in, "ghost", width=90, height=34).pack(side="right")
    custom_entry = ctk.CTkEntry(act1, height=34, corner_radius=9, border_width=1, border_color=BORDER,
                                fg_color=INK, text_color=TEXT, font=F(12), width=150,
                                placeholder_text=T("custom_ph"), placeholder_text_color=FAINT)
    tx(custom_entry, "custom_ph", "placeholder_text")
    custom_entry.pack(side="left", fill="x", expand=True, padx=(8, 12))
    if agent.mapper.custom_terms:
        custom_entry.insert(0, ", ".join(agent.mapper.custom_terms))

    out_card, out_head, masked_out = io_card(pa, "out_title", "out_hint")
    out_card.grid(row=3, column=0, sticky="nsew")
    btn(out_head, "btn_copy", copy_masked, "outline", width=92, height=30).pack(side="right")
    masked_out.tag_config("fake", background=TEAL_BG, foreground=TEAL)
    src.bind("<Control-Return>", lambda e: (do_anon(), "break")[1], add=True)

    # ===== Restore =====
    pr = pages["tab_restore"]
    pr.grid_columnconfigure(0, weight=1)
    pr.grid_rowconfigure(0, weight=1, uniform="io"); pr.grid_rowconfigure(2, weight=1, uniform="io")
    rin_card, _, reply = io_card(pr, "reply_title", "reply_hint")
    rin_card.grid(row=0, column=0, sticky="nsew")
    act2 = clear(pr); act2.grid(row=1, column=0, sticky="ew", pady=12)
    def do_restore():
        txt = reply.get("1.0", "end-1c")
        if not txt.strip(): return gui.flash(T("need_reply"))
        _, n = show_restored(restored_out, txt)
        gui.flash(T("restored_n", n=n) if n else T("no_known"), "real" if n else "info")
    def copy_restored():
        t = restored_out.get("1.0", "end-1c")
        if not t.strip(): return gui.flash(T("no_output"))
        put_clipboard(t); gui.flash(T("copied_real"), "real")
    def clear_rest():
        reply.delete("1.0", "end"); restored_out.delete("1.0", "end"); gui.flash(T("cleared"))
    btn(act2, "btn_restore", do_restore, "primary", width=170, height=42).pack(side="left")
    ctk.CTkLabel(act2, text="Ctrl+Enter", font=F(11), text_color=FAINT).pack(side="left", padx=12)
    btn(act2, "btn_clear", clear_rest, "ghost", width=90, height=34).pack(side="right")
    rout_card, rout_head, restored_out = io_card(pr, "real_title", "real_hint")
    rout_card.grid(row=2, column=0, sticky="nsew")
    btn(rout_head, "btn_copy", copy_restored, "danger", width=92, height=30).pack(side="right")
    tx(ctk.CTkLabel(rout_head, font=F(11, "bold"), height=22, corner_radius=11, fg_color=CORAL_BG,
                    text_color=CORAL), "dont_send", fmt="  %s  ").pack(side="right", padx=(0, 10))
    restored_out.tag_config("real", background=CORAL_BG, foreground=CORAL)
    reply.bind("<Control-Return>", lambda e: (do_restore(), "break")[1], add=True)

    # ===== Ledger =====
    pd = pages["tab_ledger"]
    bar = clear(pd); bar.pack(fill="x", pady=(0, 12))
    search = ctk.CTkEntry(bar, height=34, width=320, corner_radius=9, border_width=1, border_color=BORDER,
                          fg_color=INK, text_color=TEXT, font=F(12), placeholder_text=T("search_ph"),
                          placeholder_text_color=FAINT)
    tx(search, "search_ph", "placeholder_text").pack(side="left")
    ledcount = ctk.CTkLabel(bar, text="", font=F(12), text_color=FAINT); ledcount.pack(side="left", padx=12)

    def do_export():
        p = filedialog.asksaveasfilename(parent=root, defaultextension=".json",
                                         initialfile="maskboard-ledger-%s.json" % time.strftime("%Y-%m-%d"))
        if p:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(agent.mapper.export_data(), f, ensure_ascii=False, indent=1)
            gui.flash(T("exported"), "real")
    def do_import():
        p = filedialog.askopenfilename(parent=root, filetypes=[("JSON", "*.json")])
        if not p: return
        try:
            with open(p, encoding="utf-8") as f: d = json.load(f)
            n = agent.mapper.import_entries(d.get("entries", []))
        except Exception as ex:
            return gui.flash(T("import_failed", e=ex), "warn")
        gui.refresh(); gui.flash(T("imported", n=n), "ok")
    def do_clear():
        if not agent.mapper.entries: return gui.flash(T("ledger_empty_already"))
        if messagebox.askyesno(T("reset_title"), T("reset_q"), parent=root):
            agent.mapper.clear(); gui.refresh(); gui.flash(T("reset_done"))
    btn(bar, "reset", do_clear, "danger", width=90).pack(side="right")
    btn(bar, "import", do_import, "secondary", width=100).pack(side="right", padx=(0, 8))
    btn(bar, "export", do_export, "secondary", width=100).pack(side="right", padx=(0, 8))

    led_card = card(pd); led_card.pack(fill="both", expand=True)
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except Exception: pass
    style.configure("Ledger.Treeview", background=SURF, fieldbackground=SURF, foreground=TEXT,
                    rowheight=int(34 * sc), borderwidth=0, relief="flat", font=(UI, 11))
    style.configure("Ledger.Treeview.Heading", background=SURF, foreground=FAINT, borderwidth=0,
                    relief="flat", font=(UI, 10, "bold"), padding=(10, 8))
    style.map("Ledger.Treeview", background=[("selected", "#1C2A3D")], foreground=[("selected", TEXT)])
    style.map("Ledger.Treeview.Heading", background=[("active", SURF)], foreground=[("active", MUTED)])
    style.layout("Ledger.Treeview", [("Ledger.Treeview.treearea", {"sticky": "nswe"})])
    tree_wrap = clear(led_card); tree_wrap.pack(fill="both", expand=True, padx=(12, 6), pady=10)
    tree = ttk.Treeview(tree_wrap, columns=("type", "real", "fake"), show="headings", style="Ledger.Treeview")
    for col, key, w in (("type", "col_type", 100), ("real", "col_real", 360), ("fake", "col_token", 360)):
        tree.column(col, width=w, anchor="w", stretch=(col != "type"))
        retranslate.append(lambda col=col, key=key: tree.heading(col, text=T(key), anchor="w"))
    tree.tag_configure("odd", background="#141A26")
    vsb = ctk.CTkScrollbar(tree_wrap, command=tree.yview, button_color=BORDER, button_hover_color=BORDER2)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y"); tree.pack(side="left", fill="both", expand=True)
    empty_lbl = tx(ctk.CTkLabel(led_card, font=F(13), text_color=FAINT, justify="center"), "empty_ledger")
    search.bind("<KeyRelease>", lambda e: gui.refresh())

    # ---------- bridge used by the watcher thread ----------
    TONES = {"ok": TEAL, "real": CORAL, "info": MUTED, "warn": CORAL}
    class Gui:
        def refresh(self):
            def _():
                q = search.get().strip().lower()
                tree.delete(*tree.get_children())
                def shown(e):
                    return T("secret_shown", n=len(e["real"])) if e.get("secret") else e["real"]
                rows = [e for e in agent.mapper.entries
                        if not q or q in shown(e).lower() or q in e["fake"].lower() or q in type_label(e["type"]).lower()]
                for i, e in enumerate(reversed(rows)):
                    tree.insert("", "end", values=(type_label(e["type"]), shown(e), e["fake"]),
                                tags=("odd",) if i % 2 else ())
                total = len(agent.mapper.entries)
                ledcount.configure(text=T("rows_q", k=len(rows), n=total) if q else T("rows", n=total))
                ledger_badge.configure(text=T("ledger_badge", n=total) if total else "")
                if total: empty_lbl.place_forget()
                else: empty_lbl.place(relx=0.5, rely=0.5, anchor="center")
                if auto_var.get() != agent.auto: auto_var.set(agent.auto)
                dot.configure(text_color=TEAL if agent.auto else FAINT)
                hero_title.configure(text=T("hero_on" if agent.auto else "hero_off"))
                hero_sub.configure(text=T(("hero_on_smart" if agent.mode == "smart" else "hero_on_mask")
                                          if agent.auto else "hero_off_sub"))
            root.after(0, _)
        def flash(self, msg, tone="info"):
            stamp = time.strftime("%H:%M")
            root.after(0, lambda: last_lbl.configure(text="%s   %s" % (stamp, msg), text_color=TONES.get(tone, MUTED)))
        def capture(self, kind, original, result, n):
            def _():
                if kind == "restore":
                    show_page("tab_restore"); set_text(reply, original); show_restored(restored_out, original)
                    self.flash(T("cap_restore", n=n) if n else T("cap_restore_0"), "real" if n else "info")
                else:
                    show_page("tab_mask"); set_text(src, original); show_fakes(masked_out, result); set_badge(n)
                    self.flash(T("cap_mask", n=n) if n else T("cap_mask_0"), "ok" if n else "info")
            root.after(0, _)
    gui = Gui(); agent.gui = gui

    def apply_lang():
        for fn in retranslate: fn()
        tabs.configure(values=[T(k) for k in PAGES]); tabs.set(T(current[0]))
        mode_seg.configure(values=[T(k) for k in MODE_KEYS.values()]); mode_seg.set(T(MODE_KEYS[agent.mode]))
        draw_caps(); gui.refresh()
        if icon is not None:
            try: icon.update_menu()
            except Exception: pass

    # ---------- tray and notifications ----------
    icon = None
    if pystray and PILImage is not None:
        def tray_show(*_): root.after(0, lambda: (root.deiconify(), root.lift(), root.focus_force()))
        def tray_quit(*_):
            try: icon.stop()
            except Exception: pass
            agent.stop(); root.after(0, root.destroy)
        menu = pystray.Menu(
            pystray.MenuItem(lambda i: T("tray_show"), tray_show, default=True),
            pystray.MenuItem(lambda i: T("tray_auto_on" if agent.auto else "tray_auto_off"),
                             lambda *_: set_auto(not agent.auto)),
            pystray.MenuItem(lambda i: T("tray_mode_smart" if agent.mode == "smart" else "tray_mode_mask"),
                             lambda *_: root.after(0, toggle_mode)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda i: T("tray_mask"), lambda *_: agent.clip_anonymize()),
            pystray.MenuItem(lambda i: T("tray_restore"), lambda *_: agent.clip_restore()),
            pystray.MenuItem(lambda i: T("tray_reset"), lambda *_: root.after(0, do_clear)),
            pystray.MenuItem(lambda i: T("tray_keys"), lambda *_: root.after(0, show_hotkeys)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda i: T("tray_quit"), tray_quit),
        )
        try:
            icon = pystray.Icon("maskboard", app_icon(64), APP_NAME, menu)
            threading.Thread(target=icon.run, daemon=True).start()
        except Exception as ex:
            icon = None; print("Tray icon unavailable:", ex)

    def notify(title, msg):
        if icon is not None:
            try: icon.notify(msg, title); return
            except Exception: pass
        if sys.platform.startswith("linux"):
            try:
                import subprocess; subprocess.Popen(["notify-send", "-i", "security-high", title, msg])
            except Exception: pass
    agent.notify = notify

    def on_close():
        if sys.platform == "win32" and icon is not None:
            root.withdraw(); notify(APP_NAME, T("bg_win"))
        elif sys.platform != "win32":
            root.iconify(); notify(APP_NAME, T("bg_other"))    # not every Linux desktop has a tray
        else:
            agent.stop(); root.destroy()
    root.bind_all("<Control-q>", lambda e: (agent.stop(), root.destroy()))
    root.protocol("WM_DELETE_WINDOW", on_close)

    if keyboard:
        try:
            hk = keyboard.GlobalHotKeys({
                "<ctrl>+<alt>+a": agent.clip_anonymize,
                "<ctrl>+<alt>+r": agent.clip_restore,
                "<ctrl>+<alt>+t": lambda: set_auto(not agent.auto),
            })
            hk.daemon = True; hk.start()
        except Exception as ex:
            gui.flash(T("keys_failed", e=ex), "warn")

    clip_ok = False
    if pyperclip:
        try:
            pyperclip.paste(); agent.sync_now(); clip_ok = True
        except Exception as ex:
            gui.flash(T("clip_failed", e=ex), "warn")
    else:
        gui.flash(T("no_pyperclip"), "warn")
    caps[:] = [("cap_clip", clip_ok), ("cap_keys", bool(keyboard)), ("cap_tray", icon is not None),
               ("cap_recopy", bool(agent.counter))]
    apply_lang(); show_page(PAGES[0])
    set_auto(clip_ok, quiet=True)
    if not keyboard:
        gui.flash(T("keys_off"), "warn")
    elif clip_ok:
        gui.flash(T("ready_long"), "ok")
    legacy = agent.mapper.legacy_count()
    if legacy:
        gui.flash(T("legacy", n=legacy), "warn")

    threading.Thread(target=agent.watch_loop, daemon=True).start()
    root.mainloop(); agent.stop()


def _migrate_store():
    """Move a ledger written under an earlier name (ClipVeil, Anonim Ajan) to its new place."""
    for old in LEGACY_STORES:
        if os.path.exists(STORE): return
        if os.path.exists(old):
            try: os.replace(old, STORE)
            except OSError: pass


def main():
    args = sys.argv[1:]
    if args[:1] == ["--export-icon"]:
        print("Icon written:", export_icon(args[1] if len(args) > 1 else "maskboard.ico")); return
    if pyperclip is None:
        print("Warning: pyperclip is missing — clipboard and hotkeys are off; the boxes still work.\n"
              "  pip install pyperclip pynput")
    _migrate_store()
    agent = Agent()
    set_lang(agent.mapper.settings.get("lang") or detect_lang())
    try:
        run_gui(agent)
    except SystemExit:
        raise
    except Exception as ex:
        # A windowed build has no console: log the error, show it, and exit for real.
        import traceback
        detail = traceback.format_exc()
        log = os.path.join(HOME, "maskboard-error.log")
        try:
            with open(log, "w", encoding="utf-8") as f: f.write(detail)
        except Exception:
            log = None
        print(detail)
        try:
            import tkinter as tk
            from tkinter import messagebox
            r = tk.Tk(); r.withdraw()
            messagebox.showerror(T("crash_title"), "%s\n\n%s" % (ex, T("crash_details", p=log) if log else ""))
        except Exception:
            pass
        os._exit(1)


if __name__ == "__main__":
    main()
