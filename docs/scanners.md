# Public malware scanners

The Python tools in `tools/` check files against **known-good** copies, which catches
anything that isn't stock WordPress, plugin or theme code. Signature scanners catch **known-bad**
code, including inside premium plugins and child themes that have no reference copy. Use both.

Run these on the **downloaded copy**, never against the live server (you can't on a
managed host anyway). `tools/public_scanners.sh SITE_DIR` runs whichever are installed.

| Scanner | What it adds | Install |
|---|---|---|
| **ClamAV** | Free antivirus engine. On its own it misses most PHP web shells. | `apt install clamav` / `brew install clamav`, then `freshclam` |
| **Linux Malware Detect (rfxn) signatures** | The ClamAV signatures that actually catch PHP shells and web injectors (`rfxn.hdb`, `rfxn.ndb`, `rfxn.yara`). | Download from https://www.rfxn.com/projects/linux-malware-detect/ and copy the `rfxn.*` files into the ClamAV database folder (or point `CLAM_DB_DIRS` at them) |
| **SaneSecurity signatures** | Extra ClamAV signatures (phishing, web malware). | https://sanesecurity.com/usage/ |
| **YARA + php-malware-finder** | Rules aimed at obfuscated PHP (eval chains, encoded payloads, packers). Noisy by design. | `apt install yara` / `brew install yara`; `git clone https://github.com/jvoisin/php-malware-finder`. Use only `data/php.yar`; the files under `data/whitelists/` are exclusion lists, not detection rules |
| **WP-CLI** `wp core verify-checksums` | Same check as `verify_core.py`. Safe offline: it doesn't load WordPress. | https://wp-cli.org |

Also useful:
- **WPScan / Patchstack / Wordfence vulnerability databases**: look up each plugin and theme
  version to find the likely way in.
- **Sucuri SiteCheck** (sitecheck.sucuri.net): outside view of the live site (spam,
  redirects, blocklists).
- **Wordfence plugin** on the live site after cleanup, for ongoing scanning and a firewall. Its
  free scanner compares files against wordpress.org much like `verify_extensions.py`.

**Things not to do on the hacked copy:** don't run `wp plugin verify-checksums`, `wp eval`,
`wp db ...`, or open the site in a local PHP server. All of these load WordPress and
execute the malware. Run them on the live site (which already runs that code) or after the
rebuild.

**Reading hits:** a scanner hit in a file that `verify_core.py` / `verify_extensions.py`
reported as byte-identical to wordpress.org is a false positive. A hit anywhere else is a
file to read.
