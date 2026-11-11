# wp-rescue

Recover a hacked WordPress site **without server access**, with an AI coding agent
(Claude Code, Codex, Cursor, ...) doing most of the work.

Made for web developers and site owners on shared or managed hosting (WP Engine, Kinsta,
SiteGround, cPanel hosts...). You download the site and its database, the agent finds
what's wrong, a clean copy is rebuilt from official sources, and you upload it back.

## Quick start

1. Download the site (all files, including hidden ones) and a database export (`.sql`).
   `AGENTS.md` step 2 explains how, including from WP Engine.
2. Put this repo next to them and open your agent in this folder:
   ```
   git clone https://github.com/IslePrince/wp-rescue
   cd wp-rescue
   claude        # or your agent of choice; it reads CLAUDE.md / AGENTS.md
   ```
3. Tell it: *"My client's WordPress site was hacked. The files are in ../hacked and the
   database is ../dump.sql. Their domain is clientsite.com and they host on WP Engine.
   Follow the playbook."*

**Or install it as a Claude skill** so it works from any folder: Claude loads it by
itself when you say a site is hacked.
```
git clone https://github.com/IslePrince/wp-rescue ~/.claude/skills/wp-rescue
```
(For one project only, clone it into that project's `.claude/skills/wp-rescue` instead.
For the Claude apps, zip the folder and upload it in the Skills section of Claude's settings.)

The agent follows **[AGENTS.md](AGENTS.md)**: lock the doors, scan, rebuild, clean the
database, swap the files, rotate passwords and keys, verify, harden. It asks you before
anything destructive on the live site.

## The tools

Python 3.8+, standard library only. Nothing to install, and nothing from the hacked site is
ever executed.

| Tool | What it does |
|---|---|
| `tools/verify_core.py SITE` | Compares every core file with wordpress.org's official checksums: modified, missing, and extra (planted) files. |
| `tools/verify_extensions.py SITE` | Compares every plugin and theme with the same version on wordpress.org. Lists premium/custom code you must replace from the vendor, fake plugins, mu-plugins and drop-ins. |
| `tools/scan_files.py SITE` | Heuristic scan for obfuscated eval, code run from request input, PHP in uploads or disguised as images, `.htaccess`/`.user.ini` tricks, injected JS. |
| `tools/scan_db.py dump.sql --domain site.com` | Reads the SQL export as text (no database needed): all users with admins marked, hijacked settings, open registration, cron hooks, injected scripts and iframes. |
| `tools/rebuild.py HACKED CLEAN [--managed-host]` | Builds a clean site: fresh core, plugins and themes from wordpress.org, only verified media from uploads, new wp-config salts. Writes a report of what needs a human. |
| `tools/public_scanners.sh SITE` | Runs ClamAV (+ Linux Malware Detect and SaneSecurity signatures), YARA + php-malware-finder, and WP-CLI checksums, whichever are installed. See [docs/scanners.md](docs/scanners.md). |

`python3 tests/run_tests.py` downloads real WordPress, plants harmless fake malware, and
checks that every tool catches it and the rebuild leaves it behind.

## Limits

- Heuristics and signatures miss new tricks. The rebuild approach (replace everything
  from official sources) is what makes the result trustworthy, not the scanners.
- Premium plugins, child themes and custom code can't be checked against a reference.
  They need fresh vendor downloads or a careful read.
- Without server logs you may not find how the attacker got in. Ask your host for logs.
- If files reappear after cleanup, the way in is still open (often another site in the same
  hosting account, or stolen credentials). Involve your host.

## License

MIT. No warranty: this is help, not a guarantee. Keep the backup of the hacked state.
