#!/usr/bin/env python3
"""Scan a WordPress database export (.sql from phpMyAdmin, mysqldump, WP-CLI) for signs of a hack.

    python3 scan_db.py dump.sql [--domain example.com] [--domain cdn.example.com]

Prints: every user (administrators marked), key settings (siteurl, home, registration,
default role, active plugins, theme), cron hook names, non-standard tables, and rows
containing injected scripts / iframes / obfuscated code. --domain marks your own hosts
as expected so their <script src> tags are not reported.

Works on the text of the dump; nothing is imported and no database is needed. Read-only.
"""
import argparse
import os
import re
import sys
from collections import OrderedDict

STD = {"commentmeta", "comments", "links", "options", "postmeta", "posts", "term_relationships",
       "term_taxonomy", "termmeta", "terms", "usermeta", "users",
       # multisite
       "blogs", "blogmeta", "registration_log", "signups", "site", "sitemeta"}

Q = r"'((?:[^'\\]|\\.)*)'"           # a quoted SQL string
N = r"\s*,\s*"
SUSPECT = [
    ("HIGH", "script-src-offsite", re.compile(r"<script[^>]{0,200}?src\s*=\s*\\?[\"']?\s*(?:https?:)?//([^/\"'\\\s>]+)", re.I)),
    ("HIGH", "inline-script-obfuscated", re.compile(r"<script[^>]*>(?:(?!</script>).){0,400}?(?:eval\s*\(|atob\s*\(|fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|document\.write\s*\(\s*unescape)", re.I | re.S)),
    ("HIGH", "php-code-in-data", re.compile(r"(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(", re.I)),
    ("MED", "iframe", re.compile(r"<iframe[^>]{0,200}?src\s*=\s*\\?[\"']?\s*(?:https?:)?//([^/\"'\\\s>]+)", re.I)),
    ("MED", "hidden-link-block", re.compile(r"<(?:div|span|p)[^>]{0,80}style\s*=\s*\\?[\"'][^\"'\\]{0,80}(?:display\s*:\s*none|left\s*:\s*-\d{3,}px)[^>]*>(?:(?!</).){0,300}<a\s", re.I | re.S)),
    ("MED", "js-redirect", re.compile(r"(?:window|document|top)\.location(?:\.href)?\s*=\s*\\?[\"']https?://([^/\"'\\]+)", re.I)),
]
EMBED_OK = ("youtube.com", "youtube-nocookie.com", "vimeo.com", "google.com", "googletagmanager.com",
            "google-analytics.com", "gstatic.com", "googleapis.com", "facebook.net", "facebook.com",
            "twitter.com", "x.com", "instagram.com", "spotify.com", "soundcloud.com", "calendly.com",
            "wistia.com", "wistia.net", "jsdelivr.net", "cloudflare.com", "stripe.com", "paypal.com",
            "hubspot.com", "hsforms.net", "mailchimp.com", "typeform.com", "wp.com", "wordpress.com",
            "gravatar.com", "jquery.com", "bootstrapcdn.com", "fontawesome.com", "recaptcha.net")


def host_ok(host, own):
    host = host.lower().split(":")[0]
    for d in tuple(own) + EMBED_OK:
        if host == d or host.endswith("." + d):
            return True
    return False


def unesc(s):
    return s.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump")
    ap.add_argument("--domain", action="append", default=[], help="your own domain(s); may repeat")
    a = ap.parse_args()
    own = [d.lower().lstrip(".") for d in a.domain]

    tables, prefix = [], None
    users = OrderedDict()           # id -> dict
    caps = {}                       # user_id -> capabilities string
    options = {}
    hits = []
    cur = None

    rx_create = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?`?(\w+)`?", re.I)
    rx_insert = re.compile(r"INSERT (?:IGNORE )?INTO `?(\w+)`?", re.I)
    rx_user = re.compile(r"\(\s*(\d+)" + N + Q + N + Q + N + Q + N + Q + N + Q + N + r"'([0-9: -]+)'")
    rx_cap = re.compile(r"\(\s*\d+" + N + r"(\d+)" + N + r"'(\w*capabilities)'" + N + Q + r"\s*\)")
    rx_opt = re.compile(r"\(\s*\d+" + N + r"'(siteurl|home|users_can_register|default_role|active_plugins|template|stylesheet|admin_email|cron)'" + N + Q)

    with open(a.dump, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            m = rx_create.search(line[:300])
            if m:
                tables.append(m.group(1))
                if m.group(1).endswith("options") and prefix is None:
                    prefix = m.group(1)[:-len("options")]
            m = rx_insert.match(line.lstrip()[:300]) if line.lstrip()[:6].upper() == "INSERT" else None
            if m:
                cur = m.group(1)
            if cur is None:
                continue
            short = cur[len(prefix):] if prefix and cur.startswith(prefix) else cur
            if short == "users":
                for u in rx_user.finditer(line):
                    users[u.group(1)] = {"login": unesc(u.group(2)), "email": unesc(u.group(5)),
                                         "registered": u.group(7)}
            elif short == "usermeta":
                for c in rx_cap.finditer(line):
                    caps[c.group(1)] = unesc(c.group(3))
            elif short == "options":
                for o in rx_opt.finditer(line):
                    options[o.group(1)] = unesc(o.group(2))
            for sev, name, rx in SUSPECT:
                for h in rx.finditer(line):
                    host = h.group(1) if h.groups() else None
                    if host and host_ok(host, own):
                        continue
                    s = re.sub(r"\s+", " ", line[max(0, h.start() - 60): h.end() + 60])
                    hits.append((sev, name, cur, lineno, host, s[:220]))

    if prefix is None and tables:
        prefix = os.path.commonprefix(tables)
    print("Table prefix: %r   tables: %d" % (prefix, len(tables)))
    extra = [t for t in tables if not (prefix and t.startswith(prefix) and t[len(prefix):] in STD)]
    print("\n== NON-STANDARD TABLES: %d  (normally plugin tables; an unknown name is worth a look)" % len(extra))
    for t in extra:
        print("   " + t)

    print("\n== USERS: %d" % len(users))
    admins = []
    for uid, u in users.items():
        role = caps.get(uid, "")
        is_admin = "administrator" in role
        if is_admin:
            admins.append(u["login"])
        roles = ",".join(re.findall(r's:\d+:"([^"]+)";b:1', role)) or "?"
        print("   %s id=%-5s %-24s %-34s registered %s  roles=%s" % (
            "ADMIN" if is_admin else "     ", uid, u["login"], u["email"], u["registered"], roles))
    orphan_caps = [uid for uid, c in caps.items() if uid not in users and "administrator" in c]
    for uid in orphan_caps:
        print("   ADMIN id=%-5s (capabilities row with no matching user row - suspicious)" % uid)
    print("   -> confirm every ADMIN with the site owner. Unknown admins = attacker accounts.")

    print("\n== KEY SETTINGS")
    for k in ("siteurl", "home", "admin_email", "users_can_register", "default_role", "template", "stylesheet"):
        print("   %-18s %s" % (k, options.get(k, "(not found)")))
    if options.get("users_can_register") == "1" and options.get("default_role") in ("administrator", "editor"):
        hits.append(("HIGH", "open-registration-as-" + options["default_role"], "options", 0, None,
                     "anyone can register and become " + options["default_role"]))
    for k in ("siteurl", "home"):
        v = options.get(k, "")
        if v and own and not host_ok(re.sub(r"^https?://", "", v).split("/")[0], own):
            hits.append(("HIGH", k + "-points-offsite", "options", 0, None, v))
    ap_ = options.get("active_plugins", "")
    print("   active_plugins:")
    for p in re.findall(r's:\d+:"([^"]+)"', ap_):
        print("      " + p)
    cron = options.get("cron", "")
    hooks = sorted(set(re.findall(r's:\d+:"([A-Za-z0-9_\-\\]+)";a:\d+:\{s:32:"[0-9a-f]{32}"', cron)))
    print("\n== CRON HOOKS: %d  (unfamiliar names that match no plugin can re-infect the site)" % len(hooks))
    for h in hooks:
        print("   " + h)

    print("\n== SUSPICIOUS CONTENT: %d hit(s)" % len(hits))
    for sev in ("HIGH", "MED"):
        for s, name, table, ln, host, snip in hits:
            if s == sev:
                print("   %-4s %-28s table=%s line=%s%s\n        %s" % (
                    s, name, table, ln, (" host=" + host) if host else "", snip))
    print("\nRESULT: %d admin(s), %d suspicious hit(s)." % (len(admins), len(hits)))
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
