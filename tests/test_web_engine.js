#!/usr/bin/env node
/*
 * ClipVeil web version parity tests.
 *
 *     node tests/test_web_engine.js                 # test the engine embedded in clipveil.html
 *     node tests/test_web_engine.js path/engine.js  # test an engine in another file
 *
 * The block between ENGINE START and ENGINE END is extracted and checked against the desktop
 * expected outputs (tests/expected/*), so both versions mask the same input the same way.
 * Needs Node 18+, no packages.
 */
"use strict";
const fs = require("fs"), path = require("path");

const HERE = __dirname, ROOT = path.dirname(HERE);
const FIX = path.join(HERE, "fixtures"), EXP = path.join(HERE, "expected");
const RULES = JSON.parse(fs.readFileSync(path.join(HERE, "rules.json"), "utf8"));

function loadEngine(file) {
  file = file || path.join(ROOT, "clipveil.html");
  const src = fs.readFileSync(file, "utf8");
  const a = src.indexOf("/* ENGINE START"), b = src.indexOf("/* ENGINE END */");
  if (a < 0 || b < 0) throw new Error(file + ": ENGINE START/END markers not found");
  return new Function(src.slice(a, b) + "\nreturn ClipVeilEngine;")();
}

const reEsc = s => s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
const fixtures = () => fs.readdirSync(FIX).filter(f => !f.startsWith(".")).sort();
const store = initial => {
  let saved = initial;
  return { load: () => (saved ? JSON.parse(JSON.stringify(saved)) : null), save: o => { saved = o; }, dump: () => JSON.stringify(saved) };
};

function lineDiff(a, b) {
  const x = a.split("\n"), y = b.split("\n"), out = [];
  for (let i = 0; i < Math.max(x.length, y.length); i++)
    if (x[i] !== y[i]) { out.push("-" + (x[i] ?? "∅")); out.push("+" + (y[i] ?? "∅")); }
  return out.slice(0, 40).join("\n");
}

function checkFixture(E, name) {
  const src = fs.readFileSync(path.join(FIX, name), "utf8");
  const m = new E.Mapper(null);
  const [out] = m.anonymize(src);
  const problems = [];
  const exp = fs.readFileSync(path.join(EXP, name), "utf8");
  if (out !== exp) problems.push("output differs from the desktop version:\n" + lineDiff(exp, out));
  for (const v of RULES.leaks[name] || []) {
    const pat = /^\w+$/.test(v) ? new RegExp("(?<![A-Za-z0-9])" + reEsc(v) + "(?![A-Za-z0-9])") : new RegExp(reEsc(v));
    if (pat.test(out)) problems.push("LEAK: " + JSON.stringify(v) + " was not masked");
  }
  for (const v of RULES.keep[name] || []) if (!out.includes(v)) problems.push("OVER-MASKED: " + JSON.stringify(v));
  if (m.restore(out)[0] !== src) problems.push("restore did not give back the original");
  const [again, n] = m.anonymize(out);
  if (again !== out) problems.push("masking the masked text changed " + n + " values");
  return problems;
}

function checkConsistency(E) {
  const m = new E.Mapper(null), problems = [];
  const [a] = m.anonymize("kemal@web01:~/projects/ithub$ docker ps");
  const [b] = m.anonymize("Oct 01 09:13:44 web01 sudo[2201]:    kemal : COMMAND=/usr/bin/docker restart ithub-web-1");
  const [c] = m.anonymize("server_name ithub.sirket.com.tr;\nupstream ithub_backend { server 10.10.10.21:8080; }");
  const [d] = m.anonymize("ithub projesinde kemal kullanicisi web01 uzerinde hata aliyor");
  const tok = r => m.realToFake.get(r);
  for (const real of ["kemal", "web01", "ithub"]) {
    if (!tok(real)) { problems.push(real + " never got a token"); continue; }
    for (const [label, txt] of [["prompt", a], ["journal", b], ["nginx", c], ["plain sentence", d]])
      if (txt.includes(real)) problems.push(real + " left visible in the " + label + " message");
  }
  if (!/server_name DOMAIN_\d+;/.test(c)) problems.push("a full domain name did not become one token: " + c);
  if (tok("ithub") && !b.includes(tok("ithub") + "-web-1")) problems.push("compose container does not reuse the project token: " + b);
  return problems;
}

function checkCrlf(E) {
  const problems = [];
  for (const name of fixtures()) {
    const src = fs.readFileSync(path.join(FIX, name), "utf8");
    const [lf] = new E.Mapper(null).anonymize(src);
    const m = new E.Mapper(null);
    const [crlf] = m.anonymize(src.replace(/\n/g, "\r\n"));
    if (crlf.replace(/\r\n/g, "\n") !== lf) problems.push(name + ": CRLF output differs\n" + lineDiff(lf, crlf.replace(/\r\n/g, "\n")));
    if (m.restore(crlf)[0] !== src.replace(/\n/g, "\r\n")) problems.push(name + ": CRLF restore did not give back the original");
  }
  return problems;
}

function checkLegacyUpgrade(E) {
  const st = store({ version: 2, entries: [
    { real: "10.0.0.15", fake: "IP_5", type: "ipv4" },
    { real: "br-4c1e2f3a5b6d", fake: "HOST_10", type: "hostname" },
    { real: "appuser", fake: "KULLANICI_1", type: "config" },
    { real: "web01", fake: "HOST_3", type: "hostname" },
    { real: "ithub", fake: "PROJE_2", type: "project", prop: true },
    { real: "raporlar", fake: "AYAR_4", type: "config" }],
    counters: { IP: 5, HOST: 10, KULLANICI: 1, PROJE: 2, AYAR: 4 } });
  const m = new E.Mapper(st);
  const [out] = m.anonymize("4: br-4c1e2f3a5b6d: <UP> mtu 1500\n    inet 10.0.0.15/24 scope global br-4c1e2f3a5b6d\n" +
                            "DB_USER=appuser\nkemal@web01:~/projects/ithub$ ls\nDB_NAME=raporlar");
  const problems = [];
  for (const want of ["IFACE_1", "IP_PRIV_1/24", "DB_USER=USER_1", "@HOST_3:", "projects/PROJECT_1$", "DB_NAME=DB_1"])
    if (!out.includes(want)) problems.push("expected upgrade " + want + " missing → " + out);
  const back = m.restore("IP_5 HOST_10 KULLANICI_1 IFACE_1 IP_PRIV_1 PROJE_2 PROJECT_1 AYAR_4 DB_1")[0];
  if (back !== "10.0.0.15 br-4c1e2f3a5b6d appuser br-4c1e2f3a5b6d 10.0.0.15 ithub ithub raporlar raporlar")
    problems.push("old and new tokens did not both restore: " + back);
  const m2 = new E.Mapper(st); m2.anonymize("DB_PASSWORD=Gizli.Parola!42");
  if (st.dump().includes("Gizli.Parola!42")) problems.push("a password reached storage");
  if (JSON.stringify(m2.exportData()).includes("Gizli.Parola!42")) problems.push("a password reached the export");
  return problems;
}

// Assembled at runtime so no real-looking key sits in the repository (GitHub push protection).
function secretSamples() {
  const j = a => a.join("");
  return { Stripe: j(["sk_", "live_", "a1B2c3D4".repeat(3)]), GitHub: j(["gh", "p_", "A1b2C3d4E5".repeat(4)]),
           GitLab: j(["gl", "pat-", "x7Y8z9W0".repeat(3)]), Slack: j(["xo", "xb-", "1234567890-", "aBcDeFgHiJ"]),
           Google: j(["AI", "za", "Sy" + "Q1w2E3r4T5".repeat(3) + "abc"]), Vault: j(["hv", "s.", "Q1w2E3r4T5".repeat(3)]),
           AWS: j(["AK", "IA", "Q1W2E3R4T5Y6U7I8"]) };
}
function checkSecretFormats(E) {
  const problems = [];
  for (const [name, val] of Object.entries(secretSamples())) {
    const m = new E.Mapper(null), txt = "request rejected: " + val + " invalid";
    const [out] = m.anonymize(txt);
    if (out.includes(val)) problems.push(name + " key not recognised by its format: " + out);
    if (m.restore(out)[0] !== txt) problems.push(name + " key did not restore");
  }
  return problems;
}

function checkPasswordLanguages(E) {
  const m = new E.Mapper(null), problems = [];
  for (const key of ["password", "Passwort", "Kennwort", "contraseña", "mot_de_passe", "senha", "wachtwoord",
                     "hasło", "lösenord", "şifre", "parola"]) {
    const [out] = m.anonymize(key + "=Xy.Secret." + key.length);
    if (!new RegExp("^" + reEsc(key) + "=PASSWORD_\\d+$", "u").test(out)) problems.push(key + " → " + out);
  }
  return problems;
}

function checkTokenBoundaries(E) {
  const m = new E.Mapper(null);
  m.anonymize("ssh web01; DB_PASSWORD=Gizli.123");
  const back = m.restore("DB_HOST_1 DB_PASSWORD_1 HOST_1 PASSWORD_1 ada_HOST_1 PROJECT_1_HOST_1")[0];
  return back === "DB_HOST_1 DB_PASSWORD_1 web01 Gizli.123 ada_web01 PROJECT_1_web01" ? [] : ["boundary restore: " + back];
}

function checkUrlsAndDomains(E) {
  const m = new E.Mapper(null), problems = [];
  const cases = [
    ["185.12.34.56 test.ornek.com", /^IP_PUB_1 DOMAIN_\d+$/],
    ["prod.ornek.com ornek.com", /^DOMAIN_\d+ DOMAIN_\d+$/],
    ["curl https://web01.ornek.com/health?x=1, then http://10.10.10.20:8080/api.", /^curl URL_\d+, then URL_\d+\.$/],
    ["(https://yonetim.sirket.com.tr/panel)", /^\(URL_\d+\)$/],
    ["https://github.com/acme/repo and http://localhost:3000/x", /^https:\/\/github\.com\/acme\/repo and http:\/\/localhost:3000\/x$/],
    ["upstream app_be { } proxy_pass http://app_be;", /proxy_pass http:\/\/app_be;$/],
    ["https://ali:Gizli.Sifre9@api.ornek.com/v1", /^https:\/\/USER_\d+:PASSWORD_\d+@DOMAIN_\d+\/v1$/],
    ["https://api.ornek.com/v1?api_key=abcdef123456&x=1", /^https:\/\/DOMAIN_\d+\/v1\?api_key=\w+_\d+&x=1$/],
    ["yonetim sunucusu yine coktu", /^HOST_\d+ sunucusu/],
  ];
  for (const [txt, want] of cases) {
    const [out] = m.anonymize(txt);
    if (!want.test(out)) problems.push(JSON.stringify(txt) + " → " + JSON.stringify(out) + " (expected " + want + ")");
    if (m.restore(out)[0] !== txt) problems.push(JSON.stringify(txt) + " did not restore");
  }
  for (const e of m.exportEntries())
    if (e.real.includes("Gizli.Sifre9") || e.real.includes("abcdef123456")) problems.push("URL with credentials reached the ledger: " + e.real);
  return problems;
}

function checkClassify(E) {
  const m = new E.Mapper(null), problems = [];
  m.anonymize("kemal@web01:~$ ping 10.10.10.20");
  const ai = "IP_PRIV_1 is unreachable from HOST_1; try again as USER_1.";
  if (m.classify(ai)[0] !== "restore") problems.push("AI answer not classified as restore");
  if (m.classify("new log: 172.16.9.9 app07 error")[0] !== "anon") problems.push("new log not classified as mask");
  const back = m.restore(ai)[0];
  if (!back.includes("10.10.10.20") || !back.includes("web01") || !back.includes("kemal")) problems.push("restore incomplete: " + back);
  if (m.restore("IP_PRIV_99 unknown")[0] !== "IP_PRIV_99 unknown") problems.push("an unknown token was changed");
  return problems;
}

const CHECKS = [["consistency across messages", checkConsistency], ["Windows line endings (CRLF)", checkCrlf],
  ["upgrade from older ledgers", checkLegacyUpgrade], ["key formats (Stripe, GitHub, AWS…)", checkSecretFormats],
  ["password keys in several languages", checkPasswordLanguages], ["token boundaries", checkTokenBoundaries],
  ["domain and URL tokens", checkUrlsAndDomains], ["classify + restore", checkClassify]];

function main() {
  const E = loadEngine(process.argv[2]);
  let failed = 0;
  const report = (label, p) => {
    console.log((p.length ? "✗ " : "✓ ") + label);
    for (const x of p) console.log("    " + x.replace(/\n/g, "\n    "));
    failed += p.length ? 1 : 0;
  };
  for (const name of fixtures()) report(name, checkFixture(E, name));
  for (const [label, fn] of CHECKS) report(label, fn(E));
  console.log("\nWEB RESULT: " + failed + " failed");
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main();
module.exports = { loadEngine };
