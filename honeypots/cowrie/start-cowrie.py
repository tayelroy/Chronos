"""Cowrie entrypoint wrapper: plant Chronos breadcrumbs in the fake filesystem, then exec Cowrie.

Runs inside the cowrie/cowrie image (docker-compose.edge.yml): `python3 start-cowrie.py <twistd> <args...>`.
It copies the image's own fs.pickle, so the tree always matches the running Cowrie version, adds:

  /root/.bash_history         admin history pointing at a fake internal network (always)
  /root/.aws/config           \\ honeytoken AWS key pair from HONEYTOKEN_COWRIE_AWS_KEY_ID /
  /root/.aws/credentials      /  HONEYTOKEN_COWRIE_AWS_SECRET (only when both are set)

writes the result to $COWRIE_SHELL_FILESYSTEM (Cowrie's [shell] filesystem option), drops the
HONEYTOKEN_* variables from the environment, and replaces itself with the given command.
"""
import os
import pickle
import sys

from cowrie.core.resources import open_data_binary

# Node layout of Cowrie's fs.pickle (cowrie/shell/fs.py):
# [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
A_NAME, A_TYPE, A_SIZE, A_MODE, A_CTIME, A_CONTENTS = 0, 1, 4, 5, 6, 7
T_DIR, T_FILE = 1, 2
S_IFDIR, S_IFREG = 0o040000, 0o100000

# 192.168.50.0/24 is outside the VPC and Docker ranges: nothing real answers there.
# The canary's bait files use the same fake network (honeypots/canary_http/app.py).
BASH_HISTORY = """apt update && apt upgrade -y
systemctl status nginx
df -h
docker ps
docker compose -f /srv/billing/docker-compose.yml pull
docker compose -f /srv/billing/docker-compose.yml up -d
aws configure
aws s3 ls s3://billing-invoices-prod/
aws s3 cp /var/backups/billing-db.sql.gz s3://billing-db-backups/daily/
ssh deploy@192.168.50.12
scp /var/backups/billing-db.sql.gz deploy@192.168.50.12:/var/backups/
mysql -h 192.168.50.20 -u billing_app -p billing
crontab -l
tail -n 100 /var/log/nginx/error.log
exit
"""


def child(node, name):
    return next((c for c in node[A_CONTENTS] if c[A_NAME] == name), None)


def mkdir(parent, name, mode, ctime):
    node = child(parent, name)
    if node is None:
        node = [name, T_DIR, 0, 0, 4096, S_IFDIR | mode, ctime, [], None, None]
        parent[A_CONTENTS].append(node)
    if node[A_TYPE] != T_DIR:
        raise SystemExit(f"start-cowrie: {name} exists in fs.pickle and is not a directory")
    return node


def put_file(parent, name, data, mode, ctime):
    node = child(parent, name)
    if node is not None:
        parent[A_CONTENTS].remove(node)
    parent[A_CONTENTS].append([name, T_FILE, 0, 0, len(data), S_IFREG | mode, ctime, data, None, None])


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: start-cowrie.py <command> [args...]")
    out_path = os.environ["COWRIE_SHELL_FILESYSTEM"]
    key_id = os.environ.pop("HONEYTOKEN_COWRIE_AWS_KEY_ID", "").strip()
    secret = os.environ.pop("HONEYTOKEN_COWRIE_AWS_SECRET", "").strip()
    if bool(key_id) != bool(secret):
        raise SystemExit("start-cowrie: HONEYTOKEN_COWRIE_AWS_KEY_ID and HONEYTOKEN_COWRIE_AWS_SECRET must be set together")

    with open_data_binary("fs.pickle") as f:
        tree = pickle.load(f)
    root = mkdir(tree, "root", 0o700, 0)
    # Age the breadcrumbs relative to the stock tree so timestamps stay consistent with it.
    ctime = root[A_CTIME] + 86400 * 97

    put_file(root, ".bash_history", BASH_HISTORY.encode(), 0o600, ctime + 3600)
    planted = ["/root/.bash_history"]
    if key_id:
        aws = mkdir(root, ".aws", 0o700, ctime)
        put_file(aws, "config", b"[default]\nregion = us-east-1\noutput = json\n", 0o600, ctime)
        put_file(aws, "credentials",
                 f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n".encode(),
                 0o600, ctime)
        planted += ["/root/.aws/config", "/root/.aws/credentials"]

    with open(out_path, "wb") as f:
        pickle.dump(tree, f)
    print(f"start-cowrie: planted {', '.join(planted)} -> {out_path}", flush=True)
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])


if __name__ == "__main__":
    main()
