#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClipVeil masking regression tests.

    python tests/test_masking.py            # run
    python tests/test_masking.py --update   # rewrite expected outputs (review the diff first!)
    pytest tests/                           # also works with pytest

For every sample in tests/fixtures the masked output must equal tests/expected/<name>, leak none of
the LEAKS values, keep every KEEP value, restore to the original byte for byte, and stay unchanged
when masked again. When Node is available the web version (clipveil.html) is checked against the
same expected files. Only the engine is loaded; no GUI packages are needed.
"""
import difflib, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX, EXP = os.path.join(HERE, "fixtures"), os.path.join(HERE, "expected")


def load_engine():
    for mod in ("pyperclip", "pynput"):
        if mod not in sys.modules:
            try:
                __import__(mod)
            except Exception:
                sys.modules[mod] = types.ModuleType(mod)
    spec = importlib.util.spec_from_file_location("clipveil", os.path.join(ROOT, "clipveil.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


RULES = json.load(open(os.path.join(HERE, "rules.json"), encoding="utf-8"))
LEAKS, KEEP = RULES["leaks"], RULES["keep"]


def fixtures():
    return sorted(f for f in os.listdir(FIX) if not f.startswith("."))


def check_fixture(engine, name, update=False):
    src = open(os.path.join(FIX, name), encoding="utf-8").read()
    m = engine.Mapper(store=None)
    out, _ = m.anonymize(src)
    problems = []
    exp_path = os.path.join(EXP, name)
    if update:
        open(exp_path, "w", encoding="utf-8").write(out)
    elif not os.path.exists(exp_path):
        problems.append("no expected output — run with --update first")
    else:
        exp = open(exp_path, encoding="utf-8").read()
        if out != exp:
            diff = "".join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True), "expected", "actual", n=0))
            problems.append("output differs:\n" + diff)
    for v in LEAKS.get(name, []):
        # word-like values need a boundary: "ithub" must not match inside "github.com"
        pat = (r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])") if re.fullmatch(r"\w+", v) else re.escape(v)
        if re.search(pat, out): problems.append("LEAK: %r was not masked" % v)
    for v in KEEP.get(name, []):
        if v not in out: problems.append("OVER-MASKED: %r should be kept" % v)
    if m.restore(out)[0] != src: problems.append("restore did not give back the original")
    again, n = m.anonymize(out)
    if again != out: problems.append("masking the masked text changed %d values" % n)
    return problems


def check_consistency(engine):
    """A name keeps its token across messages and contexts."""
    m = engine.Mapper(store=None)
    problems = []
    a, _ = m.anonymize("kemal@web01:~/projects/ithub$ docker ps")
    b, _ = m.anonymize("Oct 01 09:13:44 web01 sudo[2201]:    kemal : COMMAND=/usr/bin/docker restart ithub-web-1")
    c, _ = m.anonymize("server_name ithub.sirket.com.tr;\nupstream ithub_backend { server 10.10.10.21:8080; }")
    d, _ = m.anonymize("ithub projesinde kemal kullanicisi web01 uzerinde hata aliyor")
    tok = m.real_to_fake.get
    for real in ("kemal", "web01", "ithub"):
        if not tok(real):
            problems.append("%r never got a token" % real); continue
        for label, txt in (("prompt", a), ("journal", b), ("nginx", c), ("plain sentence", d)):
            if real in txt: problems.append("%r left visible in the %s message" % (real, label))
    if not re.search(r"server_name DOMAIN_\d+;", c):
        problems.append("a full domain name did not become one token: %s" % c)
    if tok("ithub") and ("%s-web-1" % tok("ithub")) not in b:
        problems.append("compose container does not reuse the project token: %s" % b)
    return problems


def check_crlf(engine):
    """Windows clipboards use \\r\\n: every sample must mask the same way with CRLF."""
    problems = []
    for name in fixtures():
        src = open(os.path.join(FIX, name), encoding="utf-8").read()
        lf, _ = engine.Mapper(store=None).anonymize(src)
        m = engine.Mapper(store=None)
        crlf, _ = m.anonymize(src.replace("\n", "\r\n"))
        if crlf.replace("\r\n", "\n") != lf:
            diff = "".join(difflib.unified_diff(lf.splitlines(True), crlf.replace("\r\n", "\n").splitlines(True),
                                                "LF", "CRLF", n=0))
            problems.append("%s: CRLF output differs\n%s" % (name, diff))
        if m.restore(crlf)[0] != src.replace("\n", "\r\n"):
            problems.append("%s: CRLF restore did not give back the original" % name)
    return problems


def check_legacy_upgrade(engine):
    """Ledgers from older releases: a more precise type gets a new token, old tokens still restore."""
    path = os.path.join(tempfile.mkdtemp(), "ledger.json")
    json.dump({"version": 2, "entries": [
        {"real": "10.0.0.15", "fake": "IP_5", "type": "ipv4"},
        {"real": "br-4c1e2f3a5b6d", "fake": "HOST_10", "type": "hostname"},
        {"real": "appuser", "fake": "KULLANICI_1", "type": "config"},
        {"real": "web01", "fake": "HOST_3", "type": "hostname"},
        {"real": "ithub", "fake": "PROJE_2", "type": "project", "prop": True},
        {"real": "raporlar", "fake": "AYAR_4", "type": "config"}],
        "counters": {"IP": 5, "HOST": 10, "KULLANICI": 1, "PROJE": 2, "AYAR": 4}}, open(path, "w"))
    m = engine.Mapper(store=path)
    out, _ = m.anonymize("4: br-4c1e2f3a5b6d: <UP> mtu 1500\n    inet 10.0.0.15/24 scope global br-4c1e2f3a5b6d\n"
                         "DB_USER=appuser\nkemal@web01:~/projects/ithub$ ls\nDB_NAME=raporlar")
    problems = []
    for want in ("IFACE_1", "IP_PRIV_1/24", "DB_USER=USER_1", "@HOST_3:", "projects/PROJECT_1$", "DB_NAME=DB_1"):
        if want not in out: problems.append("expected upgrade %r missing → %s" % (want, out))
    back = m.restore("IP_5 HOST_10 KULLANICI_1 IFACE_1 IP_PRIV_1 PROJE_2 PROJECT_1 AYAR_4 DB_1")[0]
    if back != "10.0.0.15 br-4c1e2f3a5b6d appuser br-4c1e2f3a5b6d 10.0.0.15 ithub ithub raporlar raporlar":
        problems.append("old and new tokens did not both restore: %s" % back)
    m2 = engine.Mapper(store=path)
    m2.anonymize("DB_PASSWORD=Gizli.Parola!42")
    if "Gizli.Parola!42" in open(path, encoding="utf-8").read(): problems.append("a password reached the ledger file")
    if "Gizli.Parola!42" in json.dumps(m2.export_data()): problems.append("a password reached the export")
    return problems


def secret_samples():
    """Provider key formats, assembled at runtime so no real-looking key sits in the repository
    (GitHub push protection would reject it)."""
    j = "".join
    return {"Stripe": j(["sk_", "live_", "a1B2c3D4" * 3]), "GitHub": j(["gh", "p_", "A1b2C3d4E5" * 4]),
            "GitLab": j(["gl", "pat-", "x7Y8z9W0" * 3]), "Slack": j(["xo", "xb-", "1234567890-", "aBcDeFgHiJ"]),
            "Google": j(["AI", "za", "Sy" + "Q1w2E3r4T5" * 3 + "abc"]), "Vault": j(["hv", "s.", "Q1w2E3r4T5" * 3]),
            "AWS": j(["AK", "IA", "Q1W2E3R4T5Y6U7I8"])}


def check_secret_formats(engine):
    """Keys are recognised by format alone, without a key name, and restore."""
    problems = []
    for name, val in secret_samples().items():
        m = engine.Mapper(store=None)
        txt = "request rejected: " + val + " invalid"
        out, _ = m.anonymize(txt)
        if val in out: problems.append("%s key not recognised by its format: %s" % (name, out))
        if m.restore(out)[0] != txt: problems.append("%s key did not restore" % name)
    return problems


def check_password_languages(engine):
    """Password keys in several languages."""
    m = engine.Mapper(store=None)
    problems = []
    for key in ("password", "Passwort", "Kennwort", "contraseña", "mot_de_passe", "senha", "wachtwoord",
                "hasło", "lösenord", "şifre", "parola"):
        out, _ = m.anonymize("%s=Xy.Secret.%d" % (key, len(key)))
        if not re.fullmatch(re.escape(key) + r"=PASSWORD_\d+", out): problems.append("%s → %s" % (key, out))
    return problems


def check_token_boundaries(engine):
    """Upper-case identifiers that end like a token (DB_HOST_1) are not tokens; ada_HOST_1 is."""
    m = engine.Mapper(store=None)
    m.anonymize("ssh web01; DB_PASSWORD=Gizli.123")
    back = m.restore("DB_HOST_1 DB_PASSWORD_1 HOST_1 PASSWORD_1 ada_HOST_1 PROJECT_1_HOST_1")[0]
    want = "DB_HOST_1 DB_PASSWORD_1 web01 Gizli.123 ada_web01 PROJECT_1_web01"
    return [] if back == want else ["boundary restore: %s" % back]


def check_urls_and_domains(engine):
    """A full domain name and an http(s) address are one token; a URL with credentials is masked piecewise."""
    m = engine.Mapper(store=None)
    cases = [
        ("185.12.34.56 test.ornek.com", r"^IP_PUB_1 DOMAIN_\d+$"),
        ("prod.ornek.com ornek.com", r"^DOMAIN_\d+ DOMAIN_\d+$"),
        ("curl https://web01.ornek.com/health?x=1, then http://10.10.10.20:8080/api.", r"^curl URL_\d+, then URL_\d+\.$"),
        ("(https://yonetim.sirket.com.tr/panel)", r"^\(URL_\d+\)$"),
        ("https://github.com/acme/repo and http://localhost:3000/x", r"^https://github\.com/acme/repo and http://localhost:3000/x$"),
        ("upstream app_be { } proxy_pass http://app_be;", r"proxy_pass http://app_be;$"),
        ("https://ali:Gizli.Sifre9@api.ornek.com/v1", r"^https://USER_\d+:PASSWORD_\d+@DOMAIN_\d+/v1$"),
        ("https://api.ornek.com/v1?api_key=abcdef123456&x=1", r"^https://DOMAIN_\d+/v1\?api_key=\w+_\d+&x=1$"),
        ("yonetim sunucusu yine coktu", r"^HOST_\d+ sunucusu"),       # learned from the earlier domain
    ]
    problems = []
    for txt, want in cases:
        out, _ = m.anonymize(txt)
        if not re.search(want, out): problems.append("%r → %r (expected pattern %s)" % (txt, out, want))
        if m.restore(out)[0] != txt: problems.append("%r did not restore" % txt)
    for e in m.export_entries():
        if "Gizli.Sifre9" in e["real"] or "abcdef123456" in e["real"]:
            problems.append("URL with credentials reached the ledger: %s" % e["real"])
    return problems


def natid(nine):
    """A valid Turkish national ID built from 9 digits (test numbers are generated, never real ones)."""
    d = [int(c) for c in nine]
    d10 = (sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10
    return nine + str(d10) + str((sum(d) + d10) % 10)


def check_national_id(engine):
    """Checksum-valid 11-digit IDs are masked; phones, wrong check digits and longer numbers are not."""
    a, b = natid("123456789"), natid("987654321")
    bad = a[:-1] + str((int(a[-1]) + 1) % 10)
    m = engine.Mapper(store=None)
    cases = [("PS D:\\CorpUser\\%s\\Desktop>" % a, r"^PS D:\\CorpUser\\NATIONAL_ID_1\\Desktop>$"),
             ("tckn=%s, again %s" % (b, a), r"^tckn=NATIONAL_ID_2, again NATIONAL_ID_1$"),
             ("phone 05321234567 wrong %s longer 9%s decimal %s.5" % (bad, a, a), r"NATIONAL_ID")]
    problems = []
    for i, (txt, want) in enumerate(cases):
        out, _ = m.anonymize(txt)
        found = re.search(want, out)
        if (i < 2 and not found) or (i == 2 and found): problems.append("%r → %r" % (txt, out))
        if m.restore(out)[0] != txt: problems.append("%r did not restore" % txt)
    return problems


def check_custom_terms(engine):
    """Custom terms: case-insensitive, whole words and identifier parts, never inside a word."""
    m = engine.Mapper(store=None)
    m.set_custom(["acme", "net"])
    txt = ("ACME report, AcmeUser, ACME_Prod, x_acme, X_ACME, acme2024, myAcme, acme.example.com, "
           "network dotnet netApp NET_HOST")
    want = ("CUSTOM_1 report, CUSTOM_2User, CUSTOM_1_Prod, x_CUSTOM_3, CUSTOM_4, CUSTOM_5, CUSTOM_6, "
            "CUSTOM_3.example.com, network dotnet CUSTOM_7App CUSTOM_8_HOST")
    out, _ = m.anonymize(txt)
    problems = [] if out == want else ["custom terms:\n  got  %s\n  want %s" % (out, want)]
    if m.restore(out)[0] != txt: problems.append("custom terms did not restore")
    if m.anonymize(out)[0] != out: problems.append("masking twice changed the text")
    return problems


def check_classify(engine):
    m = engine.Mapper(store=None)
    m.anonymize("kemal@web01:~$ ping 10.10.10.20")
    ai = "IP_PRIV_1 is unreachable from HOST_1; try again as USER_1."
    problems = []
    if m.classify(ai)[0] != "restore": problems.append("AI answer not classified as restore")
    if m.classify("new log: 172.16.9.9 app07 error")[0] != "anon": problems.append("new log not classified as mask")
    back = m.restore(ai)[0]
    if "10.10.10.20" not in back or "web01" not in back or "kemal" not in back:
        problems.append("restore incomplete: %s" % back)
    if m.restore("IP_PRIV_99 unknown")[0] != "IP_PRIV_99 unknown":
        problems.append("an unknown token was changed")
    return problems


def check_web():
    """The web version (clipveil.html) must produce the same output — runs when Node is installed."""
    node = shutil.which("node")
    if not node: return None
    r = subprocess.run([node, os.path.join(HERE, "test_web_engine.js")], capture_output=True, text=True, encoding="utf-8")
    return [] if r.returncode == 0 else [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("✓")]


CHECKS = (("consistency across messages", check_consistency), ("Windows line endings (CRLF)", check_crlf),
          ("upgrade from older ledgers", check_legacy_upgrade), ("key formats (Stripe, GitHub, AWS…)", check_secret_formats),
          ("password keys in several languages", check_password_languages),
          ("token boundaries", check_token_boundaries), ("domain and URL tokens", check_urls_and_domains),
          ("national ID (T.C. kimlik no)", check_national_id), ("custom terms", check_custom_terms),
          ("classify + restore", check_classify))


# ---- pytest entry points ----
def test_fixtures():
    eng = load_engine(); bad = {n: p for n in fixtures() for p in [check_fixture(eng, n)] if p}
    assert not bad, "\n".join("%s:\n  %s" % (n, "\n  ".join(p)) for n, p in bad.items())

def test_checks():
    eng = load_engine(); bad = {label: p for label, fn in CHECKS for p in [fn(eng)] if p}
    assert not bad, "\n".join("%s:\n  %s" % (k, "\n  ".join(p)) for k, p in bad.items())

def test_web_parity():
    p = check_web()
    if p is None:
        import pytest; pytest.skip("node not found — web test skipped")
    assert not p, "\n".join(p)


def main():
    update = "--update" in sys.argv
    eng = load_engine()
    os.makedirs(EXP, exist_ok=True)
    failed = 0
    def report(label, p):
        nonlocal failed
        print(("✓ " if not p else "✗ ") + label)
        for x in p: print("    " + x.replace("\n", "\n    "))
        failed += bool(p)
    for name in fixtures():
        report(name, check_fixture(eng, name, update))
    for label, fn in CHECKS:
        report(label, fn(eng))
    if not update:
        p = check_web()
        if p is None: print("- web version (node not found, skipped)")
        else: report("web version gives the same output (clipveil.html)", p)
    print("\n%s: %d failed" % ("UPDATED" if update else "RESULT", failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
