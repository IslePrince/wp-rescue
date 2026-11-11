# Managed WordPress hosts (WP Engine, Kinsta, Flywheel, Pressable, ...)

On a managed host you don't control the server, but you usually get SFTP, phpMyAdmin,
backups, sometimes SSH with WP-CLI, and support staff who can see logs. The playbook
works the same way, with these differences.

## The host owns some files: don't delete or replace them

Managed hosts install their own code into the site, for caching, logins, security and
their dashboard. Your scanners will list it under mu-plugins and drop-ins. **Ask support
for the exact list for your plan** before deleting anything in:
- `wp-content/mu-plugins/`
- drop-ins such as `wp-content/object-cache.php` / `advanced-cache.php`
- `wp-config.php` (often generated or partly managed by the host)

On WP Engine, for example, `mu-plugins/mu-plugin.php` and `mu-plugins/wpengine-common/` are
WP Engine's own, and wp-config.php has WP Engine settings in it. Use
`rebuild.py --managed-host`: it leaves wp-config.php alone and gives you new salts to paste in.

Anything **else** in mu-plugins, or a file that looks like the host's but differs from the copy
on a fresh, clean environment of the same host, is suspect. Asking support "is this file
yours?" is normal and quick.

## WP Engine specifics

- **Ask support first.** They can see access logs (the attacker's requests and the entry
  point), and WP Engine has historically offered help with hacked sites. Ask what your plan
  includes.
- **Backup points:** User Portal → your environment → Backups. You can usually download a backup
  as a zip, with the database inside at `wp-content/mysql.sql`. Find the newest backup from
  **before** the infection: restoring it can be a shortcut, but it still holds the hole the
  attacker came through, so update everything right after, and scan it before trusting it.
- **SFTP:** User Portal → SFTP users. Create a user for this job and delete it afterwards.
- **phpMyAdmin:** linked from the environment's overview page in the User Portal.
- **SSH Gateway (WP-CLI on the live site):** add your SSH key in the User Portal, then
  `ssh <environment>@<environment>.ssh.wpengine.net`. Useful commands:
  ```
  wp core verify-checksums
  wp plugin verify-checksums --all
  wp user list --role=administrator --fields=ID,user_login,user_email,user_registered
  wp user session destroy --all
  wp user application-password list <user>
  wp role list --fields=role,name
  wp cron event list
  wp db export - > /dev/null     # or download via phpMyAdmin
  ```
  (These run on the live site, which already runs the code, so they add no risk there.)
- **Rebuild in a separate environment.** Instead of swapping files on production in place,
  upload the clean build and database to a staging or development environment, check it
  there, then copy that environment to production with WP Engine's copy-environment tool.
  Production stays up while you work, and the swap is one step. Make sure the copy replaces
  files instead of merging them; ask support if unsure.
- **Caches:** purge WP Engine's cache (User Portal or the WP Engine menu in wp-admin) and
  any CDN after the swap. Otherwise visitors may keep getting the infected pages.

## Other managed hosts

The same pattern applies: ask support for logs, the host-owned file list and a pre-infection
backup. Use `--managed-host`. Prefer a staging environment, then push to live.
