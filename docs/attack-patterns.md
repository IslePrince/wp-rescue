# What real WordPress compromises looked like

Field notes from cleaning up a multi-site shared-hosting compromise (hundreds of sites, three
separate malware families, several attackers). Hostnames, addresses and hashes are left out
on purpose; the **techniques** are what repeat from site to site. Each entry says what to
look for and which tool or playbook step covers it.

## Where malware hid

| Technique | What it looks like | Caught by |
|---|---|---|
| **Core masquerade** | Backdoors dropped deep inside WordPress's bundled libraries, e.g. `wp-includes/SimplePie/...` or `wp-includes/Requests/...`, with dull names. The path reads as "WordPress", so nobody looks. | `verify_core.py` (EXTRA files). Never skip an extra file because its path looks official. |
| **Ordinary names** | `cache.php`, `sitemap.php`, `config.php`, `class-wp-file.php`, `user-delete.php`, names of 32 hex characters. The name tells you nothing. | `verify_core.py` (unknown root PHP), `scan_files.py` |
| **Above the web root** | A file in the account's home folder, one level **above** `public_html`. Sweeps that only scan the site folder never list it. | Playbook step 2: download the level above too |
| **Remote-include stager** | A ~600-byte file that downloads code from another server, writes it to a temp file and `include`s it. No payload on disk to hash. One used DNS-over-HTTPS (`CURLOPT_DOH_URL`) so the lookup never showed in DNS logs. | `scan_files.py` (`remote-code-include`, `dns-over-https-in-php`) |
| **Polyglot images** | Files that are valid JPEG/PNG **and** contain PHP (e.g. `thumb_12.php` starting with a JPEG header, `photo.png.Phtml`). | `scan_files.py`, `rebuild.py` (PHP check on every upload) |
| **Mangled extensions** | `.phtMl`, `.png.Phtml`, `.php5`, `.phar`: case and doubling to slip past filters. | `scan_files.py` (`odd-php-extension`, `double-extension`) |
| **PHP in cache/thumbnail folders** | `wp-content/cache/.../shell.php`, thumbnail folders. Nothing legitimate puts a script in a thumbnail folder. | `scan_files.py`; `rebuild.py` never copies caches |
| **CGI helper kit** | A web-shell kit ships a folder (`ALFA_DATA/`) with Perl/Python/bash helpers and an `.htaccess` containing `Options ExecCGI` + `AddHandler cgi-script .alfa`. Scripts then run over HTTP **without PHP**, so disabling the PHP shell does not disable them. | `scan_files.py` (`htaccess-enables-cgi`, `webshell-cgi-kit`) |
| **Site-wide prepend** | `auto_prepend_file` in `.user.ini` or `.htaccess` runs a file before every page. (Wordfence and All-In-One Security legitimately do this; see false positives.) | `scan_files.py` |
| **Injected into real files** | `create_function('', "return '{$_GET[...]}'")` pasted into a genuine theme footer or plugin file. (It dies on PHP 8, which is sometimes how it gets noticed.) | `verify_extensions.py` (DIFFERS), `scan_files.py` |
| **Server exploit scripts** | Python/Perl files or compiled binaries in the account's `tmp/` folder: a kernel privilege-escalation exploit was dropped this way. That is a **server** problem, not a site problem. | `scan_files.py` (`script-or-binary-in-site`, `executable-binary`): tell the host immediately |
| **Public phpinfo pages** | `info.php`, `test.php` left from setup. They leak paths and settings attackers use. | `scan_files.py` (`phpinfo-page`), `verify_core.py` |

## Spam that replaced real pages

- **Static folders that shadow WordPress routes.** The attacker created a real folder at
  `/services/` with its own `index.html` (gambling spam). The web server serves a real folder
  **before** WordPress's routing runs, so the spam **replaced** the genuine page at that
  URL. The home page stayed clean, the sitemap was unchanged, and monitoring that checks "does it
  return 200" saw nothing wrong. Nineteen pages on one site, a different spam brand on each.
  → `scan_files.py` (`static-page-folder`, `spam-page`).
- **Search Console takeover.** Each spam folder also held a `googleXXXX.html` verification file
  and its own `sitemap.xml`. That lets the attacker verify **that folder** in Google Search
  Console and push it into Google. → `scan_files.py` (`search-console-verification-file`); the
  cleanup is in playbook step 7.
- **Removing it properly.** Renaming the folder in place (`services.old/`) kept serving the spam
  for days. Leaving an **empty** folder, or one with a deny rule, still shadows the real page,
  which then returns 403/404. **Delete the folder entirely** (keep a copy outside the site), then
  check the real URL returns the WordPress page.

## Accounts and access

- **Hidden admin.** An mu-plugin filtered `users_list_table_query_args` so the attacker's admin
  never appeared under Users → All Users. It was named like maintenance code and backdated.
  → `scan_db.py` reads users straight from the database, so hidden ones still show;
  `scan_files.py` (`hides-users-from-admin`).
- **Admins created by a script.** Two administrators created one second apart with plausible
  names (`it-…`, `maintenance-…`), while registration was off. Unauthenticated code
  (a vulnerable plugin) made them. → `scan_db.py` red flags.
- **Attackers delete their own admins.** When their shells were disabled, the attacker logged
  into **the database directly** with credentials stolen from `wp-config.php` and deleted their
  own admin accounts to cover their tracks. **A clean admin list proves nothing.** And the
  database password is compromised whenever the files were. → Playbook step 1 and step 6.
- **One site leads to all.** On shared hosting, a shell on one site could read every other
  site's `wp-config.php` in reach (and the kit had a "find all wp-config files" button and a
  "mass-infect every file under a path" button). **Every site in the same hosting account
  is compromised if one is.**
- **Stolen FTP passwords.** One FTP account was used from dozens of different IP addresses. FTP and
  SFTP passwords are usually stolen **from someone's PC** (an info-stealer on the client's or
  agency's computer). A new password typed on the same PC is stolen again.
- **Access is sold.** Requests carried a referrer from a hacking marketplace and a
  "marketplace verification bot" checking the shell still worked. Several unrelated attackers
  held access at once. A partial cleanup leaves the access listed for sale.
- **Domain hijack.** Two domains had their **nameservers changed at the registrar**: no
  web shell needed. → Playbook step 1: registrar login, 2FA, transfer lock, check nameservers.
- **Weak defaults.** `default_role` set to editor/author on sites with registration off: harmless
  until registration gets switched on. → `scan_db.py` (`default-role-elevated`).

## Lessons about the cleanup itself

- **Hunt by content and checksum, not by size or name.** A payload's file size matched dozens of
  legitimate images and core files. Deleting by size would have destroyed real data.
- **"No hits" is not "clean".** Detectors looking for PHP never saw static HTML spam. Say
  which kinds of attack you checked for, not "the site is clean".
- **Don't demote or delete accounts on heuristics alone.** Automated cleanup that demoted
  "new" admins hit real users after a username changed case. Confirm with the owner.
- **Don't "fix" a 500 error by deleting a protective `.htaccess` line** (e.g. `Options -Indexes`).
  Find what is actually failing.
- **Quarantine means MOVE OUT of the web root**, never rename in place.
- **Files at permission `000` or owned by root** you can't read or delete are usually the
  **host's** containment. Ask the host; don't fight it.
- **Without server logs you may never learn the way in.** Ask the host for logs in the first
  hour: some keep them only a few days.
