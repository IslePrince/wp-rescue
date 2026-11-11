# Known false positives: don't "fix" these

All seen in real cleanups. A hit on one of these is expected; check the plugin is
actually installed and the file matches the vendor's copy, then move on.

| Hit | Why it's legitimate |
|---|---|
| `.user.ini` / `.htaccess` `auto_prepend_file` → `wordfence-waf.php` | Wordfence's firewall loads this way. |
| `.user.ini` `auto_prepend_file` → `aios-bootstrap.php` | All-In-One Security's firewall. |
| `wp-content/wflogs/*.php` | Wordfence's own cache/config files. |
| `wp-content/mu-plugins/_patchstack.php` | Patchstack's firewall loader. |
| `wp-content/cache/object/**/*.php` | W3 Total Cache object cache entries. Caches are rebuilt anyway; `rebuild.py` never copies them. |
| `object-cache.php`, `advanced-cache.php` drop-ins | Caching plugins (and managed hosts) install these. Delete only if no plugin or host owns them. |
| Divi `DisplayConditions.php`, `NumberOfViews.php`, `PageVisit.php` using `base64_decode($_COOKIE[...])` | Divi's "Display Conditions" feature. |
| Divi/Bloom `SupportCenter.php` mentioning "adminer", `Portability.php` with `$_FILES` | Genuine Elegant Themes code. |
| `<?=` inside JPEG/PNG files | Three bytes that occur by chance in compressed image data. One site produced 736 such hits. `scan_files.py` and `rebuild.py` only treat `<?php` as PHP inside images. |
| `wp-login.php?action=postpass` in logs | WordPress's own password-protected-post form. |
| php-malware-finder / YARA hits in files that `verify_core.py` / `verify_extensions.py` say are identical to wordpress.org | The rules flag obfuscation patterns that some legitimate code uses. Byte-identical to the official copy means not modified. |
| Licence checks in premium plugins (ionCube-encoded, heavy base64) | Obfuscated by the vendor. Compare with a fresh download from the vendor instead of reading it. |
| Managed-host mu-plugins (e.g. WP Engine's `mu-plugin.php`, `wpengine-common/`) | The host's own code. See [managed-hosts.md](managed-hosts.md). |

**Permission `000` or root-owned files** in the account are usually the host's containment of
something they already found, not anti-forensics by the attacker. Ask the host.
