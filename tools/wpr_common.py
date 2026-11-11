"""Shared helpers for the wp-rescue tools. Python 3.8+, standard library only."""
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile

UA = "wp-rescue/1.0 (+https://github.com/IslePrince/wp-rescue)"

CORE_DIRS = ("wp-admin", "wp-includes")


def die(msg, code=2):
    print("error: " + msg, file=sys.stderr)
    sys.exit(code)


def http_get(url, timeout=60):
    """GET a URL. Returns bytes, or None on 404. Raises on other errors."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def http_json(url):
    data = http_get(url)
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except ValueError:
        return None


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_head(path, n=8192):
    try:
        with open(path, "rb") as f:
            return f.read(n).decode("utf-8", "replace")
    except OSError:
        return ""


def wp_version(site):
    """Version claimed by wp-includes/version.php (an attacker can edit this file;
    verify_core.py checks the file itself against the checksums of that version)."""
    p = os.path.join(site, "wp-includes", "version.php")
    m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", read_head(p, 4096))
    return m.group(1) if m else None


def header_field(text, field):
    m = re.search(r"^[ \t/*#@]*" + re.escape(field) + r"\s*:\s*(.+)$", text, re.M | re.I)
    return m.group(1).strip() if m else None


def plugin_main(plugin_dir):
    """(main_file, name, version) for a plugin folder, or (None, None, None)."""
    try:
        names = sorted(os.listdir(plugin_dir))
    except OSError:
        return None, None, None
    for n in names:
        p = os.path.join(plugin_dir, n)
        if n.endswith(".php") and os.path.isfile(p):
            head = read_head(p)
            name = header_field(head, "Plugin Name")
            if name:
                return n, name, header_field(head, "Version")
    return None, None, None


def theme_info(theme_dir):
    """(name, version, parent_template) from style.css, or (None, None, None)."""
    head = read_head(os.path.join(theme_dir, "style.css"))
    name = header_field(head, "Theme Name")
    if not name:
        return None, None, None
    return name, header_field(head, "Version"), header_field(head, "Template")


def safe_extract(zip_bytes, dest, strip_top=False):
    """Extract a zip refusing absolute paths and '..' (zip-slip). Returns file count."""
    count = 0
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            if strip_top:
                name = name.split("/", 1)[1] if "/" in name else ""
            if not name or name.endswith("/"):
                continue
            target = os.path.realpath(os.path.join(dest, name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                die("refusing unsafe path in zip: " + info.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            count += 1
    return count


def walk_files(root):
    """Relative paths of every regular file under root (no symlink following)."""
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            if os.path.isfile(p) and not os.path.islink(p):
                yield os.path.relpath(p, root).replace(os.sep, "/")


def check_site(site):
    if not os.path.isdir(site):
        die(site + " is not a folder")
    if not os.path.isdir(os.path.join(site, "wp-includes")):
        die(site + " does not look like a WordPress root (no wp-includes/). "
            "Point at the folder that holds wp-config.php.")
