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
from wpr_common import CORE_DIRS, check_site, spam_terms, walk_files  # noqa: E402

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
    ("HIGH", "create-function-from-input", r"create_function\s*\([^;]{0,300}" + SG, "code"),
    ("MED", "create-function", r"create_function\s*\(", "code"),
    # Remote-include stager: a tiny file that downloads code and includes it, leaving no
    # payload on disk to find. Some hide the lookup with DNS-over-HTTPS.
    ("HIGH", "dns-over-https-in-php", r"CURLOPT_DOH_URL", "code"),
    ("HIGH", "remote-code-include", r"(?:curl_exec|file_get_contents\s*\(\s*['\"]https?:|fopen\s*\(\s*['\"]https?:)"
                                    r".{0,600}?(?:include|require)(?:_once)?\s*\(?\s*\$", "code"),
    ("MED", "tmpfile-include", r"tmpfile\s*\(\s*\).{0,400}?stream_get_meta_data.{0,300}?(?:include|require)", "code"),
    # Hides an attacker's admin account from Users > All Users.
    ("HIGH", "hides-users-from-admin", r"users_list_table_query_args", "code"),
    ("MED", "alters-user-queries", r"pre_user_query|pre_get_users|views_users", "code"),
    ("MED", "phpinfo-page", r"^\s*<\?php\s*phpinfo\s*\(\s*\)\s*;?\s*(?:\?>)?\s*$", "code"),
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
    # Lets scripts in any language run over HTTP, bypassing every PHP restriction
    # (web-shell kits ship a CGI helper folder with exactly this .htaccess).
    ("HIGH", "htaccess-enables-cgi", r"Options[^\n]*\+?ExecCGI|cgi-script|AddHandler[^\n]*\.(?:alfa|pl|py|cgi|sh)\b", "config"),
    ("HIGH", "htaccess-image-as-php", r"(?:AddHandler|AddType|SetHandler)[^\n]*(?:php|x-httpd)[^\n]*|(?:AddHandler|AddType)[^\n]*\.(?:jpe?g|png|gif|ico|txt)", "config"),
    ("MED", "htaccess-search-engine-redirect", r"RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|yandex|baidu)", "config"),
    ("MED", "htaccess-redirect-offsite", r"RewriteRule\s+[^\n]*https?://", "config"),
]
COMPILED = [(s, n, re.compile(r, re.I | re.S | re.M), k) for s, n, r, k in RULES]
KNOWN_PREPEND = r"auto_prepend_file\s*=?\s*['\"]?[^\n'\"]*(?:wordfence-waf\.php|aios-bootstrap\.php)"


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
        if re.search(r"\.php\.[a-z0-9]+$|\.(?:jpe?g|png|gif|ico)\.ph", base):
            add("HIGH", "double-extension", rel)
        if re.fullmatch(r"[0-9a-f]{32}\.php", base):
            add("MED", "random-hex-php-name", rel, "32-hex-character PHP filename")
        if "/alfa_data/" in "/" + low + "/" or low.endswith(".alfa"):
            add("HIGH", "webshell-cgi-kit", rel, "ALFA_DATA folder / .alfa CGI helper from a web-shell kit")
        if low.endswith((".pl", ".py", ".cgi", ".sh", ".bash", ".so", ".exe", ".dll")):
            add("HIGH" if "/uploads/" in "/" + low or "/tmp/" in "/" + low else "MED",
                "script-or-binary-in-site", rel, "WordPress never needs these; tell your host if found in tmp/")
        if re.fullmatch(r"google[0-9a-f]{8,}\.html|bing(?:siteauth)?\.xml|yandex_[0-9a-f]+\.html", base):
            add("MED" if "/" not in rel else "HIGH", "search-console-verification-file", rel,
                "proves ownership of the site (or of this folder) to a search engine; confirm it is the owner's")

        k = kind(rel)
        try:
            with open(path, "rb") as f:
                raw = f.read(MAX_READ)
        except OSError:
            continue
        if raw[:4] == b"\x7fELF" or (raw[:2] == b"MZ" and (low.endswith((".exe", ".dll", ".bin")) or "." not in base)):
            add("HIGH", "executable-binary", rel, "compiled program inside a website (exploit or miner?)")
            continue
        if k is None and not low.endswith(IMAGE_EXT + (".txt", ".log", ".tmp")):
            continue
        text = raw.decode("utf-8", "replace")

        if k is None:  # image / text file: should never contain PHP
            # Only "<?php" counts in images: "<?=" occurs by chance in compressed image
            # data and produced hundreds of false positives per site in real cleanups.
            if re.search(r"<\?php", text, re.I) or (not low.endswith(IMAGE_EXT) and re.search(r"<\?=|<\?\s*(?:eval|@)", text)):
                add("HIGH", "php-hidden-in-non-php-file", rel, "contents start PHP code")
            continue
        if low.endswith((".html", ".htm", ".txt")):
            terms = spam_terms(text)
            if len(terms) >= 3:
                add("HIGH", "spam-page", rel, "spam terms: " + ", ".join(terms[:6]))
            depth = rel.count("/")
            if base in ("index.html", "index.htm") and depth == 0:
                add("HIGH" if len(terms) >= 3 else "MED", "static-home-page", rel,
                    "usually served INSTEAD of WordPress's home page")
            if base in ("index.html", "index.htm") and depth >= 1 and not low.startswith("wp-"):
                add("HIGH" if len(terms) >= 3 else "MED", "static-page-folder", rel,
                    "a folder with its own index.html is served INSTEAD of the WordPress page at that URL")
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
                if name == "htaccess-auto-prepend" and re.search(KNOWN_PREPEND, text, re.I):
                    add("MED", "auto-prepend-security-plugin", rel,
                        "points at a known security plugin's firewall (Wordfence / All-In-One Security); "
                        "normal if that plugin is installed")
                    continue
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
