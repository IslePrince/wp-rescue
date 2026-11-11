#!/usr/bin/env python3
"""Scan a WordPress database export (.sql from phpMyAdmin, mysqldump, WP-CLI, host backups)
for signs of a hack.

    python3 scan_db.py dump.sql [--domain example.com ...] [--recent-days 90] [--as-of 2026-11-01]

Reports:
  * every user, and which ones hold ADMIN-LEVEL power: the administrator role, any other
    role whose definition was given admin capabilities, capabilities granted to a user
    directly, and multisite super admins
  * red flags on each admin-level account (recent sign-up, generic name, impossible
    registration date, never authored anything, email outside your domain)
  * application passwords (API logins that survive a password reset)
  * role definitions that were tampered with, and unknown roles
  * hijacked settings, open registration, cron hook names, non-standard tables
  * injected scripts / iframes / obfuscated code in any row

--domain marks your own hosts as expected (their <script src> is not reported, and admin
emails at that domain are not flagged). --as-of is the date the dump was taken (default:
the file's modification time); "recent" sign-ups are counted back from it.

Works on the text of the dump; nothing is imported and no database is needed. Read-only.
"""
import argparse
import datetime
import os
import re
import sys
from collections import OrderedDict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpr_common import php_unserialize, spam_terms  # noqa: E402

STD = {"commentmeta", "comments", "links", "options", "postmeta", "posts", "term_relationships",
       "term_taxonomy", "termmeta", "terms", "usermeta", "users",
       "blogs", "blogmeta", "registration_log", "signups", "site", "sitemeta"}  # + multisite
STD_ROLES = {"administrator", "editor", "author", "contributor", "subscriber"}
# Capabilities that let an account take over the site (install code, make admins, change settings).
STRONG_CAPS = {"manage_options", "install_plugins", "activate_plugins", "edit_plugins", "delete_plugins",
               "update_plugins", "install_themes", "edit_themes", "update_themes", "update_core",
               "promote_users", "create_users", "unfiltered_upload", "manage_network",
               "manage_network_options", "manage_network_plugins", "manage_sites"}
# Powerful but granted by some well-known plugins (e.g. WooCommerce's shop_manager can edit users).
WEAK_CAPS = {"edit_users", "delete_users", "remove_users"}
GENERIC_LOGIN = re.compile(
    r"^(?:admin[\W_]?\d+|adm\d*|administrator\d*|root|system|sysadmin|support|test\d*|tester|backup|"
    r"wp[\W_]?(?:support|admin|adm|update|updater|sys|system|config|security|service|maint\w*|user\d*)\w*|"
    r"wordpress\w*|webmaster\d+|user\d+|[a-z]{1,3}\d{3,}|[a-z0-9]{14,})$", re.I)

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
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r", "t": "\t", "0": "\0"}.get(m.group(1), m.group(1)), s)


def true_keys(d):
    return {k for k, v in (d or {}).items() if v not in (False, 0, "0", "", None)} if isinstance(d, dict) else set()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump")
    ap.add_argument("--domain", action="append", default=[], help="your own domain(s); may repeat")
    ap.add_argument("--recent-days", type=int, default=90, help="sign-ups this recent are a red flag (default 90)")
    ap.add_argument("--as-of", help="date the dump was taken, YYYY-MM-DD (default: file modification time)")
    a = ap.parse_args()
    own = [d.lower().lstrip(".") for d in a.domain]
    as_of = (datetime.datetime.strptime(a.as_of, "%Y-%m-%d") if a.as_of
             else datetime.datetime.fromtimestamp(os.path.getmtime(a.dump)))

    tables, prefix = [], None
    users = OrderedDict()           # id -> dict
    caps, apppw = {}, {}            # user_id -> raw serialized
    options, roles_raw, site_admins_raw = {}, None, None
    authored = Counter()
    hits = []
    cur = None

    rx_create = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?`?(\w+)`?", re.I)
    rx_insert = re.compile(r"INSERT (?:IGNORE )?INTO `?(\w+)`?", re.I)
    rx_user = re.compile(r"\(\s*(\d+)" + N + Q + N + Q + N + Q + N + Q + N + Q + N + r"'([0-9: -]+)'")
    rx_meta = re.compile(r"\(\s*\d+" + N + r"(\d+)" + N + r"'(\w*capabilities|_application_passwords)'" + N + Q + r"\s*\)")
    rx_opt = re.compile(r"\(\s*\d+" + N + r"'(siteurl|home|users_can_register|default_role|active_plugins|"
                        r"template|stylesheet|admin_email|cron|\w*user_roles)'" + N + Q)
    rx_sitemeta = re.compile(r"\(\s*\d+" + N + r"\d+" + N + r"'site_admins'" + N + Q)
    rx_post = re.compile(r"\(\s*\d+" + N + r"(\d+)" + N + r"'\d{4}-\d\d-\d\d")

    with open(a.dump, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            m = rx_create.search(line[:300])
            if m:
                tables.append(m.group(1))
                if m.group(1).endswith("options") and prefix is None:
                    prefix = m.group(1)[:-len("options")]
            if line.lstrip()[:6].upper() == "INSERT":
                m = rx_insert.match(line.lstrip()[:300])
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
                for c in rx_meta.finditer(line):
                    (apppw if c.group(2) == "_application_passwords" else caps)[c.group(1)] = unesc(c.group(3))
            elif short == "options":
                for o in rx_opt.finditer(line):
                    if o.group(1).endswith("user_roles"):
                        roles_raw = unesc(o.group(2))
                    else:
                        options[o.group(1)] = unesc(o.group(2))
            elif short == "sitemeta":
                for s in rx_sitemeta.finditer(line):
                    site_admins_raw = unesc(s.group(1))
            elif short == "posts":
                for p in rx_post.finditer(line):
                    authored[p.group(1)] += 1
            if short in ("posts", "options", "postmeta", "comments", "termmeta", "terms"):
                for chunk in re.split(r"\)\s*,\s*\(", line):
                    t = spam_terms(chunk)
                    if len(t) >= 3:
                        hits.append(("HIGH", "spam-content", cur, lineno, None,
                                     "row starting (%s ...: %s" % (re.sub(r"\s+", " ", chunk.lstrip("INSERT INTO `"))[:60], ", ".join(t[:6]))))
            for sev, name, rx in SUSPECT:
                for h in rx.finditer(line):
                    host = h.group(1) if h.groups() else None
                    if host and host_ok(host, own):
                        continue
                    s = re.sub(r"\s+", " ", line[max(0, h.start() - 60): h.end() + 60])
                    hits.append((sev, name, cur, lineno, host, s[:220]))

    def flag(sev, name, detail):
        hits.append((sev, name, "-", 0, None, detail))

    if prefix is None and tables:
        prefix = os.path.commonprefix(tables)
    print("Table prefix: %r   tables: %d   dump as of: %s" % (prefix, len(tables), as_of.date()))
    extra = [t for t in tables if not (prefix and t.startswith(prefix) and t[len(prefix):] in STD)]
    print("\n== NON-STANDARD TABLES: %d  (normally plugin tables; an unknown name is worth a look)" % len(extra))
    for t in extra:
        print("   " + t)

    # ---- role definitions
    print("\n== ROLE DEFINITIONS")
    roles = php_unserialize(roles_raw) if roles_raw else None
    role_caps = {}
    if not isinstance(roles, dict):
        print("   (user_roles option not found or unreadable: assuming WordPress defaults)")
    else:
        for slug, r in roles.items():
            rc = true_keys(r.get("capabilities") if isinstance(r, dict) else None)
            role_caps[slug] = rc
            strong, weak = sorted(rc & STRONG_CAPS), sorted(rc & WEAK_CAPS)
            note = ""
            if slug != "administrator" and strong:
                note = "  <- ADMIN POWERS: " + ", ".join(strong)
                flag("HIGH", "role-has-admin-powers", "role '%s' grants %s" % (slug, ", ".join(strong)))
            elif slug != "administrator" and weak:
                note = "  <- can manage users: %s (normal for WooCommerce shop_manager)" % ", ".join(weak)
                if slug != "shop_manager":
                    flag("MED", "role-can-manage-users", "role '%s' grants %s" % (slug, ", ".join(weak)))
            if slug not in STD_ROLES and not note:
                note = "  (non-default role, usually from a plugin)"
            print("   %-22s %3d caps%s" % (slug, len(rc), note))
        if "administrator" in roles and not (role_caps.get("administrator", set()) & {"manage_options"}):
            print("   NOTE: administrator role is missing manage_options (damaged roles; see playbook)")

    def admin_power(uid):
        """(is_admin_level, reason) from the user's capabilities meta."""
        granted = true_keys(php_unserialize(caps.get(uid, "")) or {})
        if "administrator" in granted:
            return True, "administrator"
        for g in sorted(granted):
            if g in role_caps and role_caps[g] & STRONG_CAPS:
                return True, "role '%s' has admin powers" % g
        direct = granted & STRONG_CAPS
        if direct:
            return True, "direct capability " + ", ".join(sorted(direct))
        return False, ""

    # ---- super admins (multisite)
    supers = php_unserialize(site_admins_raw) if site_admins_raw else None
    super_logins = [v for v in supers.values()] if isinstance(supers, dict) else []

    # ---- users
    print("\n== USERS: %d" % len(users))
    by_login = {u["login"]: uid for uid, u in users.items()}
    admin_rows = []
    for uid, u in users.items():
        lvl, why = admin_power(uid)
        if u["login"] in super_logins and not lvl:
            lvl, why = True, "multisite super admin"
        granted = true_keys(php_unserialize(caps.get(uid, "")) or {})
        print("   %s id=%-5s %-24s %-34s registered %s  roles=%s%s" % (
            "ADMIN" if lvl else "     ", uid, u["login"], u["email"], u["registered"],
            ",".join(sorted(granted)) or "none", ("  [" + why + "]") if lvl and why != "administrator" else ""))
        if lvl:
            admin_rows.append((uid, u, why))
    for uid, c in caps.items():
        if uid not in users and admin_power(uid)[0]:
            print("   ADMIN id=%-5s (capabilities row with no matching user row)" % uid)
            flag("HIGH", "orphan-admin-capabilities", "usermeta grants admin power to missing user id %s" % uid)
    if super_logins:
        print("\n   Multisite SUPER ADMINS (control every site in the network): " + ", ".join(super_logins))
        for login in super_logins:
            if login not in by_login:
                flag("HIGH", "super-admin-without-user", "site_admins lists '%s', which is not a user" % login)

    # ---- red flags on admin-level accounts
    print("\n== ADMIN-LEVEL ACCOUNTS: RED FLAGS (confirm EVERY admin with the owner either way)")
    def regtime(u):
        try:
            return datetime.datetime.strptime(u["registered"].strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    for uid, u, why in admin_rows:
        flags, strong = [], 0
        mine = regtime(u)
        twins = [o["login"] for oid, o, _ in admin_rows if oid != uid and mine and mine.year > 2002
                 and regtime(o) and abs((regtime(o) - mine).total_seconds()) <= 120]
        if twins:
            flags.append("created within 2 minutes of %s (scripted?)" % ", ".join(twins))
            strong += 1
        reg = None
        try:
            reg = datetime.datetime.strptime(u["registered"].strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        if reg is None or reg.year < 2003:
            flags.append("impossible registration date '%s' (row inserted by hand?)" % u["registered"])
            strong += 1
        elif reg > as_of + datetime.timedelta(days=1):
            flags.append("registered after the dump date")
            strong += 1
        elif (as_of - reg).days <= a.recent_days:
            flags.append("registered %d days before the dump" % (as_of - reg).days)
            strong += 1
        if GENERIC_LOGIN.match(u["login"]):
            flags.append("generic/random login name")
            strong += 1
        if why not in ("administrator", "multisite super admin"):
            flags.append("admin power via " + why)
            strong += 1
        if authored[uid] == 0:
            flags.append("never authored any post/page/revision")
        email_dom = u["email"].rsplit("@", 1)[-1].lower() if "@" in u["email"] else ""
        if own and email_dom and not any(email_dom == d or email_dom.endswith("." + d) for d in own):
            flags.append("email outside your domain (%s)" % email_dom)
        if uid in apppw and php_unserialize(apppw[uid]):
            flags.append("has application passwords (see below)")
        verdict = "SUSPECT" if strong >= 2 or (strong and len(flags) >= 3) else ("check" if flags else "ok")
        print("   %-8s id=%-5s %-24s %s" % (verdict, uid, u["login"], "; ".join(flags) or "no red flags"))
        if verdict == "SUSPECT":
            flag("HIGH", "suspect-admin", "id=%s %s: %s" % (uid, u["login"], "; ".join(flags)))

    # ---- application passwords
    print("\n== APPLICATION PASSWORDS (API logins that keep working after a password reset)")
    any_pw = False
    for uid, raw in apppw.items():
        entries = php_unserialize(raw)
        if not isinstance(entries, dict) or not entries:
            continue
        any_pw = True
        u = users.get(uid, {"login": "(missing user %s)" % uid})
        lvl = admin_power(uid)[0] or u.get("login") in super_logins
        for e in entries.values():
            if not isinstance(e, dict):
                continue
            def ts(k):
                v = e.get(k)
                return datetime.datetime.fromtimestamp(int(v)).strftime("%Y-%m-%d") if str(v or "").isdigit() and int(v) else "never"
            print("   %s %-24s name=%-28r created=%s last_used=%s last_ip=%s" % (
                "ADMIN" if lvl else "     ", u["login"], e.get("name", "?"), ts("created"), ts("last_used"),
                e.get("last_ip") or "-"))
        if lvl:
            flag("HIGH", "admin-application-password",
                 "%s has %d application password(s); delete unless the owner set them up" % (u["login"], len(entries)))
    if not any_pw:
        print("   (none)")

    # ---- settings
    print("\n== KEY SETTINGS")
    for k in ("siteurl", "home", "admin_email", "users_can_register", "default_role", "template", "stylesheet"):
        print("   %-18s %s" % (k, options.get(k, "(not found)")))
    dr = options.get("default_role", "")
    if dr and dr not in ("subscriber", "customer"):
        flag("MED", "default-role-elevated", "new users get the '%s' role (normally subscriber)" % dr)
    if options.get("users_can_register") == "1" and (dr in ("administrator", "editor") or role_caps.get(dr, set()) & STRONG_CAPS):
        flag("HIGH", "open-registration-as-" + dr, "anyone can register and become " + dr)
    for k in ("siteurl", "home"):
        v = options.get(k, "")
        if v and own and not host_ok(re.sub(r"^https?://", "", v).split("/")[0], own):
            flag("HIGH", k + "-points-offsite", v)
    print("   active_plugins:")
    for p in re.findall(r's:\d+:"([^"]+)"', options.get("active_plugins", "")):
        print("      " + p)
    hooks = sorted(set(re.findall(r's:\d+:"([A-Za-z0-9_\-\\]+)";a:\d+:\{s:32:"[0-9a-f]{32}"', options.get("cron", ""))))
    print("\n== CRON HOOKS: %d  (unfamiliar names that match no plugin can re-infect the site)" % len(hooks))
    for h in hooks:
        print("   " + h)

    print("\n== FINDINGS: %d" % len(hits))
    for sev in ("HIGH", "MED"):
        for s, name, table, ln, host, snip in hits:
            if s == sev:
                where = "" if table == "-" else " table=%s line=%s" % (table, ln)
                print("   %-4s %-28s%s%s\n        %s" % (s, name, where, (" host=" + host) if host else "", snip))
    print("\nRESULT: %d admin-level account(s), %d finding(s)." % (len(admin_rows), len(hits)))
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
