# Chronos command cheatsheet   (cat COMMANDS.md)

All commands run from the repo root on the Mac unless marked [core] or [sensor].
Credentials: least-privilege IAM user `chronos-operator` (policy: config/iam/chronos-operator-policy.json).

    export AWS_PROFILE=chronos          # put this in ~/.zshrc to make it the default for this project
    aws sts get-caller-identity         # should print .../user/chronos-operator

IDs
    core    i-073658c52d98d9975   chronos-soc-core   private 10.0.3.13
    sensor  i-024b46954f573b978   chronos-sensor     public 34.235.107.113

## Start / stop

From anywhere (shell function in ~/.zshrc, see below):

    chronos                             # = ./start_chronos.sh
    chronos start --no-tunnels
    chronos stop                        # = ./stop_chronos.sh
    chronos stop --all
    chronos cmds                        # print this file

From the repo:

    ./start_chronos.sh                  # start both instances if stopped, compose up both, tunnels 9000/5601/9200, opens browser
    ./start_chronos.sh --no-tunnels     # same, without tunnels
    ./stop_chronos.sh                   # stop the core only (sensor keeps collecting, events buffer on the sensor)
    ./stop_chronos.sh --all             # stop both (collection pauses)

The `chronos` function (already in ~/.zshrc on this Mac; adjust the path on another machine):

    chronos() {
      local repo="$HOME/Coding/Chronos"
      case "${1:-start}" in
        start) shift 2>/dev/null; "$repo/start_chronos.sh" "$@" ;;
        stop)  shift; "$repo/stop_chronos.sh" "$@" ;;
        cmds)  cat "$repo/COMMANDS.md" ;;
        *)     echo "usage: chronos [start [--no-tunnels] | stop [--all] | cmds]" >&2; return 2 ;;
      esac
    }

    aws ec2 describe-instances --instance-ids i-073658c52d98d9975 i-024b46954f573b978 \
      --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text

## UIs (while ./start_chronos.sh is running)

    http://localhost:5601   OpenSearch Dashboards  ->  Dashboards > "Chronos - Honeypot overview"
    http://localhost:9000   TheHive                ->  analyst@chronos.local (password below)
    http://localhost:9200   OpenSearch API

Single tunnel, if you only need one:

    aws ssm start-session --target i-073658c52d98d9975 --document-name AWS-StartPortForwardingSession \
      --parameters '{"portNumber":["5601"],"localPortNumber":["5601"]}'

## Shells (SSM, no SSH)

    aws ssm start-session --target i-073658c52d98d9975     # core
    aws ssm start-session --target i-024b46954f573b978     # sensor
    cd /home/ssm-user/Chronos                              # repo on both instances

TheHive credentials [core]:

    sudo grep THEHIVE_ /home/ssm-user/Chronos/.env

## Deploy (instances git-pull the current branch, so push first)

    git push
    scripts/deploy.sh core
    scripts/deploy.sh sensor

Honeytokens (README "Experiments"). One-time AWS setup (admin `default` profile + `chronos`), writes ./honeytokens.env:

    aws login --profile default                                  # root/admin session (AWS_PROFILE=chronos is exported)
    ADMIN_PROFILE=default scripts/honeytokens-provision.sh <new-account-email> <alert-email>

Then `scripts/deploy.sh core` and `scripts/deploy.sh sensor` copy what each side needs. Check:

    curl -si http://34.235.107.113/ | grep -i '^server'          # your IP's persona
    curl -s  http://34.235.107.113/.env | grep AWS_ACCESS        # bait on (404 page = off)
    [sensor] docker logs chronos-edge-cowrie 2>&1 | grep start-cowrie   # breadcrumbs planted
    [core]   docker logs --tail 20 chronos-honeytoken-poller            # CloudTrail polls and new key use

## Container status and logs

    [core]   docker compose -f docker-compose.core.yml ps
    [core]   docker logs --tail 50 chronos-triage          # alerts being created
    [core]   docker logs --tail 50 chronos-vector-core
    [sensor] docker compose -f docker-compose.edge.yml ps
    [sensor] docker logs --tail 50 chronos-edge-cowrie     # live attacker activity
    [sensor] tail -f logs/cowrie/cowrie.json | jq -c '{t:.timestamp,ip:.src_ip,e:.eventid,in:.input}'

## OpenSearch quick queries [core]

    curl -s 'localhost:9200/_cat/indices/chronos-*?v&s=index'
    curl -s 'localhost:9200/chronos-logs-*/_count'
    curl -s 'localhost:9200/chronos-logs-*/_search?size=5&sort=timestamp:desc&q=eventid:cowrie.command.input' | jq '.hits.hits[]._source | {timestamp,src_ip,input}'

## Verification [core]

    bash scripts/verify-gate1.sh        # template/pipeline/ISM, replay tagging, replay kept out of live index
    bash scripts/verify-gate2.sh        # replayed session -> exactly 1 alert; second triage run adds none
    docker run --rm -v "$PWD/config/vector:/etc/vector:ro" timberio/vector:0.34.1-alpine \
      test /etc/vector/vector-core.yaml /etc/vector/tests/vector-core.test.yaml

From the Mac:

    nc -zv -G 5 34.235.107.113 22; nc -zv -G 5 34.235.107.113 23; nc -zv -G 5 34.235.107.113 80   # open
    nc -zv -G 5 98.95.227.115 9002                                                                    # must fail

## Findings report (on the Mac, while ./start_chronos.sh is running: it tunnels 9200)

    python3 scripts/findings-report.py --exclude-ip "$(curl -s https://checkip.amazonaws.com)"
    # writes reports/findings-<date>.md in this repo; exits 2 if any section has no data yet

## DFIR [sensor]

    ls -t logs/cowrie-tty | head                                         # session recordings
    python3 scripts/dfir-tools.py --parse-ttylog logs/cowrie-tty/<sha256>
    ls -la logs/cowrie-downloads/                                        # captured payloads (never executed)
    python3 scripts/dfir-tools.py --hash logs/cowrie-downloads/<sha256>

## Cost check

    core   m7i-flex.large  ~$0.096/h  (~$16/week if left on)
    sensor t4g.micro       ~$0.0084/h (~$1.40/week)
    The core is the expensive part: ./stop_chronos.sh when you're not looking at it.

## IAM

    aws iam list-access-keys --user-name chronos-operator    # needs an admin identity, not the chronos profile
    Rotate the key: create a new one in the console (IAM > Users > chronos-operator), then
    aws configure --profile chronos, then delete the old key.
