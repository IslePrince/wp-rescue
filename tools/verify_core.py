#!/usr/bin/env python3
"""Compare WordPress core files against the official checksums from wordpress.org.

    python3 verify_core.py SITE_DIR [--version 6.8.3] [--locale en_US]

Reports core files that were MODIFIED, are MISSING, or are EXTRA (files inside
wp-admin/ or wp-includes/ that WordPress never ships, plus unknown PHP files in the
site root). Exit code 1 when anything is found. Read-only: never changes the site.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpr_common import CORE_DIRS, check_site, die, http_json, md5_file, walk_files, wp_version  # noqa: E402

# Files that legitimately sit in the root of a WordPress site but are not in core checksums.
ROOT_EXPECTED = {"wp-config.php", ".htaccess", "robots.txt", "favicon.ico", ".user.ini",
                 "php.ini", "web.config", "sitemap.xml", "ads.txt", "humans.txt"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("site")
    ap.add_argument("--version", help="override the version read from wp-includes/version.php")
    ap.add_argument("--locale", default="en_US")
    a = ap.parse_args()
    check_site(a.site)

    ver = a.version or wp_version(a.site)
    if not ver:
        die("could not read the WordPress version; pass --version")
    url = "https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s" % (ver, a.locale)
    data = http_json(url)
    sums = (data or {}).get("checksums")
    if not isinstance(sums, dict) or not sums:
        die("wordpress.org has no checksums for version %s / locale %s. "
            "Try --locale en_US, or --version with the version the site really runs." % (ver, a.locale))
    # Older API shape nests by version.
    if ver in sums and isinstance(sums[ver], dict):
        sums = sums[ver]

    modified, missing, extra, content_diff = [], [], [], []
    for rel, want in sorted(sums.items()):
        p = os.path.join(a.site, rel)
        in_content = rel.startswith("wp-content/")
        if not os.path.isfile(p):
            if not in_content:  # bundled themes/plugins are often deleted on purpose
                missing.append(rel)
            continue
        if md5_file(p) != want:
            (content_diff if in_content else modified).append(rel)

    for d in CORE_DIRS:
        base = os.path.join(a.site, d)
        if os.path.isdir(base):
            for rel in walk_files(base):
                full = d + "/" + rel
                if full not in sums:
                    extra.append(full)
    for n in sorted(os.listdir(a.site)):
        p = os.path.join(a.site, n)
        if os.path.isfile(p) and n not in sums and n not in ROOT_EXPECTED:
            low = n.lower()
            if low.endswith((".php", ".phtml", ".phar", ".inc")) or ".php" in low or low.startswith("."):
                extra.append(n)

    print("WordPress core %s (%s): %d files checked" % (ver, a.locale, len(sums)))
    for title, items, note in (
        ("MODIFIED core files", modified, "core files never need editing; treat as infected"),
        ("EXTRA files in core folders / site root", extra, "WordPress does not ship these; usually backdoors"),
        ("MISSING core files", missing, "replace core from a fresh download"),
        ("Bundled wp-content files that differ", content_diff,
         "often just a newer bundled theme/plugin; verify_extensions.py checks those properly"),
    ):
        print("\n== %s: %d  (%s)" % (title, len(items), note))
        for i in items:
            print("   " + i)

    found = modified or extra or missing
    print("\nRESULT: %s" % ("core is NOT clean" if found else "core matches wordpress.org"))
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()
