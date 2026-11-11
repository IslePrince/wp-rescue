#!/usr/bin/env python3
"""Check every plugin and theme against the official copy on wordpress.org.

    python3 verify_extensions.py SITE_DIR

Plugins: compared with wordpress.org's per-version plugin checksums.
Themes:  the same version is downloaded from wordpress.org and compared file by file.
Anything not on wordpress.org (premium, custom, child themes, or FAKE plugins planted by
an attacker) is reported as UNVERIFIABLE: replace it from the vendor or review it by hand.
Also lists must-use plugins and drop-ins, which load automatically and are a favourite
hiding place. Exit code 1 when anything needs attention. Read-only.
"""
import argparse
import hashlib
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpr_common import (check_site, http_get, http_json, md5_file, plugin_main,  # noqa: E402
                        sha256_file, theme_info, walk_files)

DROPINS = {"advanced-cache.php", "object-cache.php", "db.php", "db-error.php", "install.php",
           "maintenance.php", "sunrise.php", "blog-deleted.php", "blog-inactive.php",
           "blog-suspended.php", "php-error.php", "fatal-error-handler.php"}
# Files wordpress.org leaves out of checksums or that differ harmlessly.
IGNORE = {"readme.txt", "changelog.txt", "license.txt", "LICENSE", "README.md"}


def as_list(v):
    return v if isinstance(v, list) else [v]


def check_plugin(path, slug, version):
    """Returns (status, details list)."""
    if not version:
        return "UNVERIFIABLE", ["no Version header"]
    data = http_json("https://downloads.wordpress.org/plugin-checksums/%s/%s.json" % (slug, version))
    files = (data or {}).get("files")
    if not files:
        return "UNVERIFIABLE", ["not on wordpress.org at %s (premium/custom/fake?)" % version]
    out = []
    for rel, h in sorted(files.items()):
        p = os.path.join(path, rel)
        if not os.path.isfile(p):
            continue  # missing files are harmless for security
        ok = False
        if "sha256" in h:
            ok = sha256_file(p) in as_list(h["sha256"])
        if not ok and "md5" in h:
            ok = md5_file(p) in as_list(h["md5"])
        if not ok and os.path.basename(rel) not in IGNORE:
            out.append("MODIFIED " + rel)
    for rel in walk_files(path):
        if rel not in files and os.path.basename(rel) not in IGNORE:
            out.append("EXTRA    " + rel)
    return ("DIFFERS" if out else "OK"), out


def check_theme(path, slug, version):
    if not version:
        return "UNVERIFIABLE", ["no Version in style.css"]
    z = http_get("https://downloads.wordpress.org/theme/%s.%s.zip" % (slug, version))
    if not z:
        return "UNVERIFIABLE", ["not on wordpress.org at %s (premium/custom/child?)" % version]
    ref = {}
    with zipfile.ZipFile(io.BytesIO(z)) as zf:
        for info in zf.infolist():
            if info.is_dir() or "/" not in info.filename:
                continue
            rel = info.filename.split("/", 1)[1]
            ref[rel] = hashlib.md5(zf.read(info)).hexdigest()
    out = []
    for rel in walk_files(path):
        if rel not in ref:
            if os.path.basename(rel) not in IGNORE:
                out.append("EXTRA    " + rel)
        elif md5_file(os.path.join(path, rel)) != ref[rel] and os.path.basename(rel) not in IGNORE:
            out.append("MODIFIED " + rel)
    return ("DIFFERS" if out else "OK"), out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("site")
    a = ap.parse_args()
    check_site(a.site)
    wc = os.path.join(a.site, "wp-content")
    bad = False

    print("== PLUGINS")
    pdir = os.path.join(wc, "plugins")
    for n in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
        p = os.path.join(pdir, n)
        if os.path.isfile(p):
            if n in ("index.php", "hello.php"):
                continue  # verify_core.py covers these
            print("   [LOOSE FILE]   %s  (plugin files normally live in a folder; review)" % n)
            bad = True
            continue
        main_file, name, ver = plugin_main(p)
        if not main_file:
            print("   [NO HEADER]    %s/  (no 'Plugin Name:' header - not a real plugin? review)" % n)
            bad = True
            continue
        status, details = check_plugin(p, n, ver)
        bad |= status != "OK"
        print("   [%-12s] %s %s  (%s)" % (status, n, ver or "?", name))
        for d in details[:200]:
            print("        " + d)

    print("\n== THEMES")
    tdir = os.path.join(wc, "themes")
    for n in sorted(os.listdir(tdir)) if os.path.isdir(tdir) else []:
        p = os.path.join(tdir, n)
        if not os.path.isdir(p):
            if n != "index.php":
                print("   [LOOSE FILE]   %s" % n)
                bad = True
            continue
        name, ver, parent = theme_info(p)
        if not name:
            print("   [NO HEADER]    %s/  (no style.css theme header; review)" % n)
            bad = True
            continue
        if parent:
            status, details = "UNVERIFIABLE", ["child theme of '%s': review every PHP file by hand" % parent]
        else:
            status, details = check_theme(p, n, ver)
        bad |= status != "OK"
        print("   [%-12s] %s %s  (%s)" % (status, n, ver or "?", name))
        for d in details[:200]:
            print("        " + d)

    print("\n== MUST-USE PLUGINS (wp-content/mu-plugins: always run, invisible in the plugin list)")
    mu = os.path.join(wc, "mu-plugins")
    items = list(walk_files(mu)) if os.path.isdir(mu) else []
    for rel in items:
        print("   REVIEW " + rel)
    if not items:
        print("   (none)")
    bad |= bool(items)

    print("\n== DROP-INS (wp-content/*.php that WordPress loads by name)")
    found = [n for n in sorted(os.listdir(wc)) if n in DROPINS] if os.path.isdir(wc) else []
    others = [n for n in sorted(os.listdir(wc)) if os.path.isfile(os.path.join(wc, n))
              and n.endswith(".php") and n not in DROPINS and n != "index.php"] if os.path.isdir(wc) else []
    for n in found:
        print("   REVIEW %s  (usually from a cache plugin; delete if that plugin is gone)" % n)
    for n in others:
        print("   SUSPICIOUS %s  (not a known drop-in)" % n)
    if not found and not others:
        print("   (none)")
    bad |= bool(found or others)

    print("\nRESULT: %s" % ("needs attention (see above)" if bad else "all plugins and themes match wordpress.org"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
