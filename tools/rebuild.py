#!/usr/bin/env python3
"""Build a CLEAN copy of a hacked WordPress site from fresh official downloads.

    python3 rebuild.py HACKED_DIR CLEAN_DIR [--same-versions] [--managed-host]

What goes into CLEAN_DIR:
  * WordPress core, freshly downloaded from wordpress.org (latest by default).
  * Every plugin and theme that exists on wordpress.org, freshly downloaded.
  * wp-content/uploads: ONLY media/document files, each checked for hidden PHP.
  * A fresh wp-config.php: database settings carried over, NEW security keys/salts.
    With --managed-host (WP Engine, Kinsta, Flywheel, Pressable, ...), no wp-config.php is
    written; new salts go to CLEAN_DIR.report.md for you to paste into the host's file.
  * A stock WordPress .htaccess and an uploads/.htaccess that refuses to run PHP.
Nothing else is copied. Premium plugins, custom/child themes, root files (verification
files, robots.txt) and custom wp-config lines are LISTED in CLEAN_DIR.report.md for a
human to bring over after review. Never copies anything that could execute.

The hacked copy is only read. Nothing from it is ever executed.
"""
import argparse
import os
import re
import secrets
import shutil
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpr_common import (check_site, die, http_get, plugin_main, read_head, safe_extract,  # noqa: E402
                        theme_info, walk_files, wp_version)

MEDIA_EXT = {"jpg", "jpeg", "png", "gif", "webp", "avif", "bmp", "tif", "tiff", "ico", "heic",
             "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "csv", "txt",
             "mp3", "m4a", "wav", "ogg", "oga", "flac", "mp4", "m4v", "mov", "webm", "ogv", "avi", "wmv",
             "woff", "woff2", "ttf", "otf", "eot", "css", "json", "vtt", "srt", "svg", "zip"}
# Checked for script content before copying (they can carry JavaScript or anything).
RISKY_MEDIA = {"svg", "zip", "css", "json", "txt", "csv"}

HTACCESS = """# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"""
UPLOADS_HTACCESS = """# Never run PHP from the uploads folder (added by wp-rescue).
<FilesMatch "\\.(?i:php\\d?|phtml|phar|pht|inc)$">
  Require all denied
</FilesMatch>
"""
SALT_KEYS = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
             "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT")
DB_KEYS = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "DB_CHARSET", "DB_COLLATE")


def new_salt():
    alphabet = string.ascii_letters + string.digits + "!#$%&()*+,-./:;<=>?@[]^_{|}~"
    return "".join(secrets.choice(alphabet) for _ in range(64))


def fetch_zip(kind, slug, version, latest):
    """Download a plugin/theme zip from wordpress.org. Returns (bytes, label) or (None, why)."""
    tries = []
    if latest:
        tries.append("https://downloads.wordpress.org/%s/%s.zip" % (kind, slug))
    if version:
        tries.append("https://downloads.wordpress.org/%s/%s.%s.zip" % (kind, slug, version))
    for url in tries:
        data = http_get(url)
        if data and data[:2] == b"PK":
            return data, url.rsplit("/", 1)[1]
    return None, "not on wordpress.org"


def parse_config(path):
    text = read_head(path, 1 << 20)
    vals, extras = {}, []
    for m in re.finditer(r"define\s*\(\s*['\"](\w+)['\"]\s*,\s*(.+?)\s*\)\s*;", text):
        key, raw = m.group(1), m.group(2).strip()
        if key in DB_KEYS:
            sm = re.match(r"^(['\"])(.*)\1$", raw, re.S)
            if sm and sm.group(1) == "'":
                vals[key] = re.sub(r"\\([\\'])", r"\1", sm.group(2))  # PHP single-quote unescape
            else:
                vals[key] = sm.group(2) if sm else raw
        elif key not in SALT_KEYS and key != "ABSPATH":
            extras.append(m.group(0))
    pm = re.search(r"\$table_prefix\s*=\s*['\"](\w+)['\"]", text)
    vals["table_prefix"] = pm.group(1) if pm else "wp_"
    return vals, extras


def php_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def write_config(out, vals, salts):
    lines = ["<?php", "// Rebuilt by wp-rescue. Security keys are NEW: everyone is logged out.", ""]
    for k in DB_KEYS:
        default = {"DB_HOST": "localhost", "DB_CHARSET": "utf8mb4", "DB_COLLATE": ""}.get(k, "")
        v = vals.get(k, default)
        lines.append("define( %s, %s );" % (php_str(k), php_str(v)))
    lines.append("")
    for k in SALT_KEYS:
        lines.append("define( %s, %s );" % (php_str(k), php_str(salts[k])))
    lines += ["", "$table_prefix = %s;" % php_str(vals["table_prefix"]), "",
              "define( 'WP_DEBUG', false );",
              "define( 'DISALLOW_FILE_EDIT', true ); // no editing PHP from wp-admin", "",
              "if ( ! defined( 'ABSPATH' ) ) {", "\tdefine( 'ABSPATH', __DIR__ . '/' );", "}",
              "require_once ABSPATH . 'wp-settings.php';", ""]
    with open(os.path.join(out, "wp-config.php"), "w") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hacked")
    ap.add_argument("clean")
    ap.add_argument("--same-versions", action="store_true",
                    help="download the versions the site had instead of the latest (latest is safer)")
    ap.add_argument("--managed-host", action="store_true",
                    help="host owns wp-config.php (WP Engine etc.): do not write one")
    a = ap.parse_args()
    check_site(a.hacked)
    if os.path.exists(a.clean) and os.listdir(a.clean):
        die(a.clean + " exists and is not empty")
    os.makedirs(a.clean, exist_ok=True)
    latest = not a.same_versions
    rep = ["# wp-rescue rebuild report", "", "Source (hacked, read only): `%s`" % a.hacked,
           "Clean build: `%s`" % a.clean, ""]
    manual = []

    # 1. core
    ver = wp_version(a.hacked)
    url = "https://wordpress.org/latest.zip" if latest or not ver else \
        "https://downloads.wordpress.org/release/wordpress-%s.zip" % ver
    print("core: %s" % url)
    z = http_get(url)
    if not z:
        die("could not download " + url)
    safe_extract(z, a.clean, strip_top=True)
    rep.append("## Core\nFresh from `%s` (site had %s)." % (url, ver or "unknown"))

    # 2. plugins
    rep.append("\n## Plugins")
    src_p = os.path.join(a.hacked, "wp-content", "plugins")
    dst_p = os.path.join(a.clean, "wp-content", "plugins")
    for n in sorted(os.listdir(src_p)) if os.path.isdir(src_p) else []:
        p = os.path.join(src_p, n)
        if not os.path.isdir(p):
            if n not in ("index.php", "hello.php"):
                manual.append("plugins/%s (loose file in plugins folder: probably malware)" % n)
            continue
        main_file, name, pver = plugin_main(p)
        if not main_file:
            manual.append("plugins/%s/ (no plugin header: probably malware, do not copy)" % n)
            continue
        data, label = fetch_zip("plugin", n, pver, latest)
        if data:
            shutil.rmtree(os.path.join(dst_p, n), ignore_errors=True)
            safe_extract(data, dst_p)
            rep.append("- %s: fresh `%s` (site had %s)" % (n, label, pver))
            print("plugin %s: %s" % (n, label))
        else:
            manual.append("plugins/%s/ \"%s\" %s: not on wordpress.org. Download a fresh copy from the "
                          "vendor's account page; do NOT copy the old folder" % (n, name, pver))

    # 3. themes
    rep.append("\n## Themes")
    src_t = os.path.join(a.hacked, "wp-content", "themes")
    dst_t = os.path.join(a.clean, "wp-content", "themes")
    for n in sorted(os.listdir(src_t)) if os.path.isdir(src_t) else []:
        p = os.path.join(src_t, n)
        if not os.path.isdir(p):
            continue
        name, tver, parent = theme_info(p)
        if not name:
            manual.append("themes/%s/ (no theme header: probably malware, do not copy)" % n)
            continue
        if parent:
            manual.append("themes/%s/ child theme of %s: small and site-specific; read every .php file, "
                          "then copy it over by hand" % (n, parent))
            continue
        data, label = fetch_zip("theme", n, tver, latest)
        if data:
            shutil.rmtree(os.path.join(dst_t, n), ignore_errors=True)
            safe_extract(data, dst_t)
            rep.append("- %s: fresh `%s` (site had %s)" % (n, label, tver))
            print("theme %s: %s" % (n, label))
        else:
            manual.append("themes/%s/ \"%s\" %s: not on wordpress.org. Fresh copy from the vendor" % (n, name, tver))

    # 4. uploads
    src_u = os.path.join(a.hacked, "wp-content", "uploads")
    dst_u = os.path.join(a.clean, "wp-content", "uploads")
    copied, skipped = 0, []
    if os.path.isdir(src_u):
        for rel in walk_files(src_u):
            ext = rel.rsplit(".", 1)[-1].lower() if "." in os.path.basename(rel) else ""
            src = os.path.join(src_u, rel)
            if ext not in MEDIA_EXT or re.search(r"\.php|\.phtml|\.phar", os.path.basename(rel), re.I):
                skipped.append(rel + "  (type not allowed)")
                continue
            head = read_head(src, 1 << 20)
            # "<?=" occurs by chance in compressed image data, so only "<?php" counts in images.
            if re.search(r"<\?php", head, re.I) or (ext in RISKY_MEDIA and "<?=" in head):
                skipped.append(rel + "  (contains PHP)")
                continue
            if ext in RISKY_MEDIA and re.search(r"<script|javascript:|on(?:load|error)\s*=|eval\s*\(", head, re.I):
                skipped.append(rel + "  (contains script)")
                continue
            dst = os.path.join(dst_u, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
    os.makedirs(dst_u, exist_ok=True)
    with open(os.path.join(dst_u, ".htaccess"), "w") as f:
        f.write(UPLOADS_HTACCESS)
    rep.append("\n## Uploads\n%d media file(s) copied, %d skipped." % (copied, len(skipped)))
    if skipped:
        rep.append("Skipped (look at these; real media can be re-added after checking):")
        rep += ["- `%s`" % s for s in skipped[:500]]
        if len(skipped) > 500:
            rep.append("- ... and %d more" % (len(skipped) - 500))

    # 5. wp-config + .htaccess
    salts = {k: new_salt() for k in SALT_KEYS}
    cfg = os.path.join(a.hacked, "wp-config.php")
    vals, extras = parse_config(cfg) if os.path.isfile(cfg) else ({"table_prefix": "wp_"}, [])
    rep.append("\n## wp-config.php")
    if a.managed_host:
        rep.append("Managed host: no wp-config.php written. In the HOST's wp-config.php, replace the 8 "
                   "key/salt lines with these (logs everyone out):\n\n```php")
        rep += ["define( '%s', %s );" % (k, php_str(salts[k])) for k in SALT_KEYS]
        rep.append("```")
    else:
        write_config(a.clean, vals, salts)
        rep.append("Written with the old database settings and NEW keys/salts. After you change the "
                   "database password at the host, update DB_PASSWORD in it.")
    if extras:
        rep.append("Other settings from the old file (NOT carried over; re-add only the ones you recognise):")
        rep += ["- `%s`" % e.replace("`", "'") for e in extras]
    with open(os.path.join(a.clean, ".htaccess"), "w") as f:
        f.write(HTACCESS)
    old_ht = read_head(os.path.join(a.hacked, ".htaccess"), 1 << 16)
    custom = re.sub(r"# BEGIN WordPress.*?# END WordPress", "", old_ht, flags=re.S).strip()
    if custom:
        rep.append("\n## Old .htaccess had extra rules (NOT carried over; review before re-adding)\n```\n%s\n```"
                   % custom[:4000])

    # 6. root files
    core_root = set(os.listdir(a.clean))
    leftovers = [n for n in sorted(os.listdir(a.hacked))
                 if n not in core_root and n not in ("wp-content", "wp-config.php")]
    if leftovers:
        rep.append("\n## Other files/folders in the old site root (NOT copied)")
        rep.append("Most are harmless (Google/Bing verification .html, robots.txt, other apps) but "
                   "unknown .php files here are a classic backdoor spot.")
        rep += ["- `%s`%s" % (n, "/" if os.path.isdir(os.path.join(a.hacked, n)) else "") for n in leftovers]
    wc_left = [n for n in sorted(os.listdir(os.path.join(a.hacked, "wp-content")))
               if n not in ("plugins", "themes", "uploads", "index.php")] \
        if os.path.isdir(os.path.join(a.hacked, "wp-content")) else []
    if wc_left:
        rep.append("\n## Other wp-content items (NOT copied: mu-plugins, drop-ins, caches, languages...)")
        rep.append("Caches can be regenerated. `languages/` is safe to re-download from Dashboard > Updates. "
                   "On managed hosts, the host's own mu-plugins are re-installed by the host; ask them.")
        rep += ["- `wp-content/%s`" % n for n in wc_left]

    rep.append("\n## NEEDS A HUMAN (%d)" % len(manual))
    rep += ["- " + m for m in manual] or ["- nothing"]
    report = os.path.abspath(a.clean.rstrip("/\\")) + ".report.md"
    with open(report, "w") as f:
        f.write("\n".join(rep) + "\n")
    print("\nclean build: %s\nreport:      %s  (kept OUTSIDE the site so it is never uploaded)" % (a.clean, report))
    print("needs a human: %d item(s); see the report" % len(manual))


if __name__ == "__main__":
    main()
