"""Chronos HTTP canary: logs every request as one JSON line and runs two experiments.

Personas: each source IP is pinned (sha256 of the IP) to one server persona. Personas differ only
in fingerprint (Server header, default page, 404 page) and product pages, so a difference in what
scanners request next is attributable to the persona. Adding or removing a persona reshuffles
every IP's assignment; start a new analysis window when PERSONAS changes.

Honeytoken bait: /.env, /wp-config.php.bak and a dumpable /.git/ repository each carry their own
AWS key pair from HONEYTOKEN_<BAIT>_AWS_KEY_ID / _AWS_SECRET, so a key-use alert names the file
that leaked. A bait is served only when its key pair is configured; otherwise its paths 404.
"""
import base64
import hashlib
import html
import json
import logging
import os
import re
import struct
import time
import zlib

from flask import Flask, Response, request
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)

logger = logging.getLogger("CanaryTrap")
logger.setLevel(logging.INFO)
_handler = logging.FileHandler("/app/logs/canary_access.json")
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)

METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# Fake internal network shared with the Cowrie breadcrumbs (honeypots/cowrie/start-cowrie.py).
# 192.168.50.0/24 is outside the VPC and Docker ranges, so nothing real answers there.
DB_HOST = "192.168.50.20"


# ---------------------------------------------------------------- personas

IIS_INDEX = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
</head>
<body>
<div id="container"><a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a></div>
</body>
</html>"""

IIS_404 = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>404 - File or directory not found.</title>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>404 - File or directory not found.</h2>
  <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
 </fieldset></div>
</div>
</body>
</html>"""

APACHE_VERSION = "Apache/2.4.41 (Ubuntu)"
APACHE_INDEX = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>
  </head>
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <span class="floating_element">Apache2 Ubuntu Default Page</span>
      </div>
      <div class="content_section floating_element">
        <div class="section_header section_header_red">It works!</div>
        <p>This is the default welcome page used to test the correct operation of the Apache2 server after
        installation on Ubuntu systems.</p>
      </div>
    </div>
  </body>
</html>"""

NGINX_VERSION = "nginx/1.18.0 (Ubuntu)"
NGINX_INDEX = """<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>"""
NGINX_404 = f"""<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>{NGINX_VERSION}</center>
</body>
</html>"""

ROUTER_LOGIN = """<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>GPON Home Gateway</title>
</head>
<body>
<form action="/boaform/admin/formLogin" method="post" name="cmlogin">
<table align="center">
<tr><td>Username:</td><td><input type="text" name="username" maxlength="30"></td></tr>
<tr><td>Password:</td><td><input type="password" name="psd" maxlength="30"></td></tr>
<tr><td colspan="2"><input type="submit" value="Login"></td></tr>
</table>
<input type="hidden" name="submit-url" value="/admin/login.asp">
</form>
%s
</body>
</html>"""
ROUTER_PING = """<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>Ping Diagnosis</title></head>
<body><h4>Ping Diagnosis</h4><p>Ping is running, please wait...</p></body>
</html>"""

PHPUNIT_EVAL = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"


def phpunit_eval(body):
    """Answer the usual CVE-2017-9841 probes (echo md5(...) or a literal) as if PHP ran them."""
    m = re.search(r"md5\(\s*(?:(['\"])(.*?)\1|(\w+))\s*\)", body)
    if m:
        return hashlib.md5((m.group(2) if m.group(1) else m.group(3)).encode()).hexdigest()
    m = re.search(r"\b(?:echo|print)\s*\(?\s*(['\"])(.*?)\1", body)
    return m.group(2) if m else ""


def apache_pages(path, body):
    if path.endswith(PHPUNIT_EVAL):
        return 200, "text/html; charset=UTF-8", phpunit_eval(body), {"X-Powered-By": "PHP/7.4.3"}
    return None


def router_pages(path, body):
    if path == "/boaform/admin/formLogin":
        return 200, "text/html", ROUTER_LOGIN % '<p><font color="red">ERROR: bad password!</font></p>', {}
    if path == "/boaform/admin/formPing":
        return 200, "text/html", ROUTER_PING, {}
    return None


PERSONAS = {
    "iis": {
        "headers": {"Server": "Microsoft-IIS/10.0", "X-Powered-By": "ASP.NET"},
        "index": IIS_INDEX,
        "not_found": lambda path: IIS_404,
        "pages": lambda path, body: None,
    },
    "apache-php": {
        "headers": {"Server": APACHE_VERSION},
        "index": APACHE_INDEX,
        "not_found": lambda path: (
            '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>404 Not Found</title>\n'
            "</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n<hr>\n"
            f"<address>{APACHE_VERSION} Server at {html.escape(request.host)} Port 80</address>\n</body></html>\n"
        ),
        "pages": apache_pages,
    },
    "nginx": {
        "headers": {"Server": NGINX_VERSION},
        "index": NGINX_INDEX,
        "not_found": lambda path: NGINX_404,
        "pages": lambda path, body: None,
    },
    "router-boa": {
        "headers": {"Server": "Boa/0.94.14rc21"},
        "index": ROUTER_LOGIN % "",
        "not_found": lambda path: (
            "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n"
            f"The requested URL {html.escape(path)} was not found on this server.\n</BODY></HTML>\n"
        ),
        "pages": router_pages,
    },
}
PERSONA_NAMES = sorted(PERSONAS)


def persona_for(ip):
    digest = hashlib.sha256(ip.encode()).digest()
    return PERSONA_NAMES[int.from_bytes(digest[:8], "big") % len(PERSONA_NAMES)]


# ---------------------------------------------------------------- honeytoken bait

def aws_pair(bait):
    key_id = os.environ.get(f"HONEYTOKEN_{bait}_AWS_KEY_ID", "").strip()
    secret = os.environ.get(f"HONEYTOKEN_{bait}_AWS_SECRET", "").strip()
    if bool(key_id) != bool(secret):
        raise SystemExit(f"HONEYTOKEN_{bait}_AWS_KEY_ID and HONEYTOKEN_{bait}_AWS_SECRET must be set together")
    return (key_id, secret) if key_id else None


def filler(seed, label, length):
    """Stable random-looking text (app keys, salts) so bait is identical across restarts."""
    return base64.b64encode(hashlib.sha512(f"{seed}:{label}".encode()).digest()).decode()[:length]


def dotenv(key_id, secret):
    return f"""APP_NAME=billing-api
APP_ENV=production
APP_KEY=base64:{filler(secret, "app_key", 43)}=
APP_DEBUG=false
APP_URL=https://billing.internal

LOG_CHANNEL=stack
LOG_LEVEL=warning

DB_CONNECTION=mysql
DB_HOST={DB_HOST}
DB_PORT=3306
DB_DATABASE=billing
DB_USERNAME=billing_app
DB_PASSWORD={filler(secret, "db", 20)}

CACHE_DRIVER=redis
QUEUE_CONNECTION=sqs
SESSION_DRIVER=redis
REDIS_HOST=192.168.50.21

AWS_ACCESS_KEY_ID={key_id}
AWS_SECRET_ACCESS_KEY={secret}
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=billing-invoices-prod
SQS_PREFIX=https://sqs.us-east-1.amazonaws.com/billing
""".encode()


def wp_config(key_id, secret):
    salts = "\n".join(
        f"define( '{name}', '{filler(secret, name, 64)}' );"
        for name in ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                     "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT")
    )
    return f"""<?php
/**
 * The base configuration for WordPress
 */

define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_prod' );
define( 'DB_PASSWORD', '{filler(secret, "wp_db", 18)}' );
define( 'DB_HOST', '{DB_HOST}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

{salts}

// WP Offload Media: uploads go to S3
define( 'AS3CF_SETTINGS', serialize( array(
    'provider' => 'aws',
    'access-key-id' => '{key_id}',
    'secret-access-key' => '{secret}',
) ) );

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {{
	define( 'ABSPATH', __DIR__ . '/' );
}}

require_once ABSPATH . 'wp-settings.php';
""".encode()


def git_repo(key_id, secret):
    """A small dumpable repository (loose objects + index) whose committed .env.production holds the key.

    Returns {path under .git/: (bytes, contains_token)}.
    """
    author = "Dana Whitfield <dana.whitfield@billing.internal>"
    commit_time = 1757331842  # 2025-09-08
    files = {
        "README.md": b"# billing-api\n\nInternal invoicing API (Laravel 10).\n\n## Deploy\n\n"
                     b"    cp .env.production .env\n    php artisan migrate --force\n",
        "composer.json": b'{\n    "name": "billing/billing-api",\n    "type": "project",\n'
                         b'    "require": {\n        "php": "^8.1",\n        "laravel/framework": "^10.10",\n'
                         b'        "aws/aws-sdk-php": "^3.283"\n    }\n}\n',
        ".env.production": dotenv(key_id, secret),
        "routes/api.php": b"<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\n"
                          b"Route::get('/invoices/{id}', [InvoiceController::class, 'show']);\n",
    }
    out = {}

    def store(kind, data):
        raw = b"%s %d\x00" % (kind, len(data)) + data
        sha = hashlib.sha1(raw).hexdigest()
        out[f"objects/{sha[:2]}/{sha[2:]}"] = (zlib.compress(raw), key_id.encode() in data)
        return sha

    blobs = {path: store(b"blob", data) for path, data in files.items()}

    def write_tree(prefix):
        children = {}
        for path in blobs:
            if path.startswith(prefix):
                name, _, rest = path[len(prefix):].partition("/")
                children[name] = bool(rest)
        entries = []
        # Git orders tree entries by name, comparing directories as "name/".
        for name in sorted(children, key=lambda n: n + "/" if children[n] else n):
            if children[name]:
                entries.append(b"40000 " + name.encode() + b"\x00" + bytes.fromhex(write_tree(prefix + name + "/")))
            else:
                entries.append(b"100644 " + name.encode() + b"\x00" + bytes.fromhex(blobs[prefix + name]))
        return store(b"tree", b"".join(entries))

    tree = write_tree("")
    message = "Production config for billing deploy"
    stamp = f"{author} {commit_time} +0000"
    commit = store(b"commit", f"tree {tree}\nauthor {stamp}\ncommitter {stamp}\n\n{message}\n".encode())

    index = [b"DIRC" + struct.pack(">II", 2, len(blobs))]
    for path in sorted(blobs, key=str.encode):
        name = path.encode()
        entry = struct.pack(">10I", commit_time, 0, commit_time, 0, 66307, 0, 0o100644, 1000, 1000,
                            len(files[path]))
        entry += bytes.fromhex(blobs[path]) + struct.pack(">H", min(len(name), 0xFFF)) + name
        index.append(entry + b"\x00" * (8 - len(entry) % 8))
    index_bytes = b"".join(index)
    index_bytes += hashlib.sha1(index_bytes).digest()

    reflog = f"{'0' * 40} {commit} {stamp}\tcommit (initial): {message}\n".encode()
    for path, data in {
        "HEAD": b"ref: refs/heads/main\n",
        "config": b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n'
                  b'\tlogallrefupdates = true\n[remote "origin"]\n\turl = git@github.com:billing-internal/billing-api.git\n'
                  b'\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n'
                  b'\tmerge = refs/heads/main\n',
        "description": b"Unnamed repository; edit this file 'description' to name the repository.\n",
        "COMMIT_EDITMSG": message.encode() + b"\n",
        "info/exclude": b"# git ls-files --others --exclude-from=.git/info/exclude\n",
        "refs/heads/main": commit.encode() + b"\n",
        "logs/HEAD": reflog,
        "logs/refs/heads/main": reflog,
        "index": index_bytes,
    }.items():
        out[path] = (data, False)
    return out


def build_bait():
    """{request path: (bait name, content type, bytes, contains_token)} for every configured bait."""
    bait = {}
    if pair := aws_pair("DOTENV"):
        bait["/.env"] = ("dotenv", "text/plain", dotenv(*pair), True)
    if pair := aws_pair("WPCONFIG"):
        bait["/wp-config.php.bak"] = ("wp-config", "application/octet-stream", wp_config(*pair), True)
    if pair := aws_pair("GIT"):
        for path, (data, has_token) in git_repo(*pair).items():
            bait[f"/.git/{path}"] = ("git", "application/octet-stream", data, has_token)
    return bait


BAIT = build_bait()


# ---------------------------------------------------------------- request handling

@app.route("/", defaults={"path": ""}, methods=METHODS)
@app.route("/<path:path>", methods=METHODS)
def catch_all(path):
    path = f"/{path}"
    src_ip = request.remote_addr
    # Exploit payloads usually ride in the body; read at most 2 KB so a large POST cannot exhaust memory.
    body = request.stream.read(2048).decode("utf-8", errors="replace")
    persona_name = persona_for(src_ip)
    persona = PERSONAS[persona_name]
    headers = dict(persona["headers"])
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "canary_http_hit",
        "src_ip": src_ip,
        "method": request.method,
        "path": path,
        "query": request.query_string.decode("utf-8", errors="replace")[:4096],
        "body": body,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "headers": dict(request.headers),
        "persona": persona_name,
    }

    if path in BAIT:
        name, content_type, payload, has_token = BAIT[path]
        status = 200
        log_entry["bait"] = name
        log_entry["honeytoken_served"] = has_token
    elif path in ("/", "/index.html"):
        status, content_type, payload = 200, "text/html", persona["index"]
    elif page := persona["pages"](path, body):
        status, content_type, payload, extra = page
        headers.update(extra)
    else:
        status, content_type, payload = 404, "text/html", persona["not_found"](path)

    log_entry["status"] = status
    logger.info(json.dumps(log_entry))
    return Response(payload, status=status, headers=headers, content_type=content_type)


class PersonaRequestHandler(WSGIRequestHandler):
    """http.server always sends its own "Server: Werkzeug/x Python/y" before the app's headers, which would
    give the canary away next to the persona's Server header. Send only the status line and Date."""

    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, request_handler=PersonaRequestHandler)
