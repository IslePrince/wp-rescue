#!/usr/bin/env python3
"""Heuristic malware scan of a downloaded WordPress site (files only).

    python3 scan_files.py SITE_DIR [--include-core] [--json report.json]

Looks for the things that keep showing up in hacked WordPress sites: obfuscated eval,
code run straight from request input, PHP hidden in uploads or disguised as images,
.htaccess / .user.ini tricks, odd PHP extensions, and injected JavaScript.
wp-admin/ and wp-includes/ are skipped by default because verify_core.py checks them
exactly; pass --include-core to scan them too.

Heuristics produce false positives (some legitimate plugins obfuscate their licence
code). Every HIGH hit needs a human or agent to read the file; never delete on a hit
alone, and never execute any file from the hacked copy. Read-only.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpr_common import CORE_DIRS, check_site, walk_files  # noqa: E402

PHP_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phar", ".inc", ".suspected")
ODD_PHP_EXT = PHP_EXT[1:]
IMAGE_EXT = (".jpg", ".jpeg", ".png", ".gif", ".ico", ".webp", ".bmp", ".svg", ".avif", ".tif", ".tiff")
TEXT_EXT = PHP_EXT + (".js", ".html", ".htm", ".txt", ".css", ".json", ".xml", ".svg", ".ico", ".sql")
MAX_READ = 4 * 1024 * 1024

FN = r"(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)"
DEC = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)"
SG = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)"

RULES = [  # (severity, name, regex, applies_to)
    ("HIGH", "eval-of-decoded-data", FN + r"\s*\(\s*(?:@?\s*" + DEC + r"\s*\(\s*)+", "code"),
    ("HIGH", "exec-of-request-input", FN + r"\s*\(\s*@?\s*(?:stripslashes\s*\(\s*)?" + SG, "code"),
    ("HIGH", "call-from-request-input", SG + r"\s*\[[^\]]{1,40}\]\s*\(", "code"),
    ("HIGH", "variable-function-from-input", r"\$(?P<v>\w+)\s*=\s*" + SG + r"\s*\[[^\]]{1,40}\]\s*;.{0,200}?\$(?P=v)(?:\(|\s*\(\s*[$'\"@])", "code"),
    ("HIGH", "include-of-non-php-file", r"(?:include|require)(?:_once)?\s*\(?\s*['\"][^'\"]+\.(?:ico|png|jpe?g|gif|txt|css|svg|log|tmp)['\"]", "code"),
    ("HIGH", "include-of-escaped-path", r"@?(?:include|require)(?:_once)?\s*\(?\s*['\"][^'\"]*\\(?:x[0-9a-fA-F]{2}|[0-7]{3})", "code"),
    ("HIGH", "write-file-from-input", r"(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,200}" + SG, "code"),
    ("HIGH", "preg-replace-eval-modifier", r"preg_replace\s*\(\s*['\"](.)[^'\"]*\1[imsxuADSUX]*e[imsxuADSUX]*['\"]", "code"),
    ("MED", "create-function", r"create_function\s*\(", "code"),
    ("MED", "long-encoded-blob", r"['\"][A-Za-z0-9+/=]{3000,}['\"]", "code"),
    ("MED", "hex-escaped-string", r"(?:\\x[0-9a-fA-F]{2}){40,}", "code"),
    ("MED", "chr-chain", r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){12,}", "code"),
    ("MED", "goto-spaghetti", r"(?:goto\s+\w+;.{0,80}){25,}", "code"),
    ("MED", "globals-obfuscation", r"\$GLOBALS\s*\[\s*['\"][^'\"]*\\x", "code"),
    ("MED", "error-reporting-off-and-eval", r"error_reporting\s*\(\s*0\s*\).{0,500}" + FN + r"\s*\(", "code"),
    ("HIGH", "js-charcode-payload", r"String\.fromCharCode\(\s*(?:\d+\s*,\s*){30,}", "js"),
    ("MED", "js-eval-atob", r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(", "js"),
    ("MED", "js-document-write-unescape", r"document\.write\s*\(\s*unescape\s*\(", "js"),
    ("MED", "js-injected-script-loader", r"createElement\(\s*['\"]script['\"]\s*\).{0,300}(?:atob|fromCharCode|\\x[0-9a-f]{2})", "js"),
    ("HIGH", "htaccess-auto-prepend", r"auto_(?:prepend|append)_file", "config"),
    ("HIGH", "htaccess-image-as-php", r"(?:AddHandler|AddType|SetHandler)[^\n]*(?:php|x-httpd)[^\n]*|(?:AddHandler|AddType)[^\n]*\.(?:jpe?g|png|gif|ico|txt)", "config"),
    ("MED", "htaccess-search-engine-redirect", r"RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|yandex|baidu)", "config"),
    ("MED", "htaccess-redirect-offsite", r"RewriteRule\s+[^\n]*https?://", "config"),
]
COMPILED = [(s, n, re.compile(r, re.I | re.S), k) for s, n, r, k in RULES]


def kind(rel):
    low = rel.lower()
    base = os.path.basename(low)
    if base in (".htaccess", ".user.ini", "php.ini", "web.config"):
        return "config"
    if low.endswith(PHP_EXT):
        return "code"
    if low.endswith((".js", ".html", ".htm")):
        return "js"
    return None


def snippet(text, m):
    s = text[max(0, m.start() - 40): m.end() + 40]
    s = re.sub(r"\s+", " ", s)
    return (s[:160] + "...") if len(s) > 160 else s


def scan(site, include_core):
    hits = []

    def add(sev, rule, rel, detail=""):
        hits.append({"severity": sev, "rule": rule, "file": rel, "detail": detail})

    for rel in walk_files(site):
        top = rel.split("/", 1)[0]
        if top in CORE_DIRS and not include_core:
            continue
        low = rel.lower()
        base = os.path.basename(low)
        path = os.path.join(site, rel)

        # --- structural checks (no reading needed)
        if "/uploads/" in "/" + low and low.endswith(PHP_EXT) and base != "index.php":
            add("HIGH", "php-in-uploads", rel, "uploads should only hold media")
        if low.endswith(ODD_PHP_EXT):
            add("HIGH", "odd-php-extension", rel, "runnable PHP under an unusual extension")
        if base.startswith(".") and low.endswith(PHP_EXT):
            add("MED", "hidden-php-file", rel)
        if re.search(r"\.php\.[a-z0-9]+$|\.(?:jpe?g|png|gif|ico)\.php$", base):
            add("HIGH", "double-extension", rel)

        k = kind(rel)
        if k is None and not low.endswith(IMAGE_EXT + (".txt", ".log", ".tmp")):
            continue
        try:
            with open(path, "rb") as f:
                text = f.read(MAX_READ).decode("utf-8", "replace")
        except OSError:
            continue

        if k is None:  # image / text file: should never contain PHP
            if "<?php" in text or re.search(r"<\?=|<\?\s*(?:eval|@)", text):
                add("HIGH", "php-hidden-in-non-php-file", rel, "contents start PHP code")
            continue
        if k == "code" and base == "index.php" and len(text) < 200 and "silence" in text.lower():
            continue  # the stock "Silence is golden" placeholder
        if k == "js" and low.endswith((".html", ".htm")) and re.search(r"<\?php", text):
            add("HIGH", "php-hidden-in-html", rel)
        if k == "code" and base == "wp-config.php":
            tail = text.split("wp-settings.php", 1)
            if len(tail) == 2 and re.search(r"\S", re.sub(r"^\s*['\"]?\s*\)?\s*;", "", tail[1]).replace("?>", "")):
                add("HIGH", "code-after-wp-settings", rel, "wp-config.php runs code after loading WordPress")
        for sev, name, rx, applies in COMPILED:
            if applies != k and not (applies == "js" and k == "code" and "<script" in text):
                continue
            m = rx.search(text)
            if m:
                add(sev, name, rel, snippet(text, m))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("site")
    ap.add_argument("--include-core", action="store_true")
    ap.add_argument("--json", help="also write all hits to this JSON file")
    a = ap.parse_args()
    check_site(a.site)
    hits = scan(a.site, a.include_core)
    order = {"HIGH": 0, "MED": 1}
    hits.sort(key=lambda h: (order[h["severity"]], h["file"], h["rule"]))
    files = {}
    for h in hits:
        files.setdefault((order[h["severity"]], h["file"]), []).append(h)
    for sev in ("HIGH", "MED"):
        group = [(f, hs) for (o, f), hs in files.items() if o == order[sev]]
        print("\n== %s: %d file(s)" % (sev, len(group)))
        for f, hs in sorted(group):
            print("   " + f)
            for h in hs:
                print("      - %s%s" % (h["rule"], ("  | " + h["detail"]) if h["detail"] else ""))
    if a.json:
        with open(a.json, "w") as out:
            json.dump(hits, out, indent=1)
    high = sum(1 for h in hits if h["severity"] == "HIGH")
    print("\nRESULT: %d HIGH, %d MED hit(s). Read every HIGH file before deciding; "
          "heuristics are not proof." % (high, len(hits) - high))
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
