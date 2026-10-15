#!/bin/bash
# Provision self-hosted AWS honeytoken keys. Run from the Mac; safe to re-run.
#
#   scripts/honeytokens-provision.sh <new-account-email> <alert-email>
#
# Identities (both must belong to the Chronos account):
#   ADMIN_PROFILE    (default "default")  root/admin session: Organizations, Chronos IAM, SNS, instance profile.
#   OPERATOR_PROFILE (default "chronos")  IAM user chronos-operator. Root can't call sts:AssumeRole, so for the
#                    length of this run only, this user may assume the member account's OrganizationAccountAccessRole
#                    (inline policy removed on exit).
#
# Chronos account: AWS Organization (if none), member account "chronos-honeytokens", SCP that denies every
#   action to every IAM user in that account, role ChronosCoreRole (the core's current role + assume the
#   reader role + publish alerts) swapped onto chronos-soc-core, SNS topic chronos-honeytoken-alerts + email.
# Member account: one IAM user + access key per bait, each with an inline deny-everything policy and nothing
#   else; role ChronosHoneytokenReader (cloudtrail:LookupEvents, ec2:DescribeRegions) trusted by ChronosCoreRole.
# Output: honeytokens.env (gitignored, mode 600). Never commit it: the account id in the keys and ARNs would let
#   anyone tie these keys to this public repository.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib/ssm.sh
source scripts/lib/ssm.sh

ACCOUNT_EMAIL="${1:?usage: honeytokens-provision.sh <new-account-email> <alert-email>}"
ALERT_EMAIL="${2:?usage: honeytokens-provision.sh <new-account-email> <alert-email>}"
ADMIN=(--profile "${ADMIN_PROFILE:-default}" --region us-east-1)
OPER=(--profile "${OPERATOR_PROFILE:-chronos}" --region us-east-1)
ACCOUNT_NAME="chronos-honeytokens"
CORE_ROLE="ChronosCoreRole"
READER_ROLE="ChronosHoneytokenReader"
TOPIC_NAME="chronos-honeytoken-alerts"
SCP_NAME="chronos-honeytokens-deny-iam-users"
TEMP_POLICY="chronos-honeytoken-provisioning"
# <bait>:<IAM user name>. The names are what an attacker sees from sts:GetCallerIdentity.
BAITS="DOTENV:billing-api-prod WPCONFIG:wp-offload-media GIT:billing-deploy COWRIE:s3-backup-sync"
OUT="honeytokens.env"

admin() { aws "${ADMIN[@]}" "$@"; }
oper() { aws "${OPER[@]}" "$@"; }
retry() {  # retry <tries> <cmd...>: IAM and new accounts are eventually consistent
  local n="$1"; shift
  for _ in $(seq 1 "$n"); do "$@" && return 0; sleep 10; done
  "$@"
}
envval() { [[ -f "$OUT" ]] && grep -E "^$1=" "$OUT" | tail -n 1 | cut -d= -f2- || true; }

MGMT=$(admin sts get-caller-identity --query Account --output text)
OPER_ARN=$(oper sts get-caller-identity --query Arn --output text)
[[ "$OPER_ARN" == "arn:aws:iam::$MGMT:user/"* ]] || { echo "[-] $OPER_ARN is not an IAM user in $MGMT" >&2; exit 1; }
OPER_USER="${OPER_ARN##*/}"
echo "[*] Chronos account $MGMT (admin profile ${ADMIN_PROFILE:-default}, operator $OPER_USER)"

# ---- Organization + member account --------------------------------------------------------------------------
if ! admin organizations describe-organization >/dev/null 2>&1; then
  echo "[*] Creating AWS Organization (all features) with $MGMT as management account"
  admin organizations create-organization --feature-set ALL >/dev/null
fi
MASTER=$(admin organizations describe-organization --query Organization.MasterAccountId --output text)
[[ "$MASTER" == "$MGMT" ]] || { echo "[-] $MGMT belongs to an organization managed by $MASTER" >&2; exit 1; }

HT=$(admin organizations list-accounts --query "Accounts[?Name=='$ACCOUNT_NAME' && Status=='ACTIVE'].Id | [0]" --output text)
if [[ -z "$HT" || "$HT" == None ]]; then
  echo "[*] Creating member account $ACCOUNT_NAME <$ACCOUNT_EMAIL>"
  req=$(admin organizations create-account --email "$ACCOUNT_EMAIL" --account-name "$ACCOUNT_NAME" \
    --iam-user-access-to-billing DENY --query CreateAccountStatus.Id --output text)
  while :; do
    read -r state HT reason < <(admin organizations describe-create-account-status --create-account-request-id "$req" \
      --query 'CreateAccountStatus.[State,AccountId,FailureReason]' --output text)
    case "$state" in
      SUCCEEDED) break ;;
      FAILED) echo "[-] Account creation failed: $reason" >&2; exit 1 ;;
      *) printf .; sleep 10 ;;
    esac
  done
  echo
fi
echo "[+] Honeytoken account $HT"

# ---- SCP: no IAM user in the honeytoken account may do anything ---------------------------------------------
ROOT_ID=$(admin organizations list-roots --query 'Roots[0].Id' --output text)
if [[ $(admin organizations list-roots --query "Roots[0].PolicyTypes[?Type=='SERVICE_CONTROL_POLICY'].Status | [0]" --output text) != ENABLED ]]; then
  admin organizations enable-policy-type --root-id "$ROOT_ID" --policy-type SERVICE_CONTROL_POLICY >/dev/null
fi
SCP_DOC='{"Version":"2012-10-17","Statement":[{"Sid":"NoIamUserMayAct","Effect":"Deny","Action":"*","Resource":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*"}}}]}'
SCP_ID=$(admin organizations list-policies --filter SERVICE_CONTROL_POLICY --query "Policies[?Name=='$SCP_NAME'].Id | [0]" --output text)
if [[ -z "$SCP_ID" || "$SCP_ID" == None ]]; then
  SCP_ID=$(admin organizations create-policy --type SERVICE_CONTROL_POLICY --name "$SCP_NAME" \
    --description "Honeytoken account: IAM users (the bait keys) can never act" --content "$SCP_DOC" \
    --query Policy.PolicySummary.Id --output text)
else
  admin organizations update-policy --policy-id "$SCP_ID" --content "$SCP_DOC" >/dev/null
fi
if [[ $(admin organizations list-targets-for-policy --policy-id "$SCP_ID" --query "Targets[?TargetId=='$HT'] | length(@)" --output text) == 0 ]]; then
  admin organizations attach-policy --policy-id "$SCP_ID" --target-id "$HT"
fi
echo "[+] SCP $SCP_NAME attached to $HT"

# ---- Chronos account: alert topic, ChronosCoreRole on the core -----------------------------------------------
TOPIC_ARN=$(admin sns create-topic --name "$TOPIC_NAME" --query TopicArn --output text)
if [[ $(admin sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" --query "Subscriptions[?Endpoint=='$ALERT_EMAIL'] | length(@)" --output text) == 0 ]]; then
  admin sns subscribe --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint "$ALERT_EMAIL" >/dev/null
  echo "[!] Confirm the SNS subscription email sent to $ALERT_EMAIL"
fi

read -r ASSOC_ID CUR_PROFILE_ARN < <(admin ec2 describe-iam-instance-profile-associations \
  --filters "Name=instance-id,Values=$CHRONOS_SOC_ID" "Name=state,Values=associated" \
  --query 'IamInstanceProfileAssociations[0].[AssociationId,IamInstanceProfile.Arn]' --output text)
if ! admin iam get-role --role-name "$CORE_ROLE" >/dev/null 2>&1; then
  SRC_ROLE=$(admin iam get-instance-profile --instance-profile-name "${CUR_PROFILE_ARN##*/}" \
    --query 'InstanceProfile.Roles[0].RoleName' --output text)
  echo "[*] Creating $CORE_ROLE from the core's current role $SRC_ROLE"
  admin iam create-role --role-name "$CORE_ROLE" --description "chronos-soc-core only (not the sensor)" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  for arn in $(admin iam list-attached-role-policies --role-name "$SRC_ROLE" --query 'AttachedPolicies[].PolicyArn' --output text); do
    admin iam attach-role-policy --role-name "$CORE_ROLE" --policy-arn "$arn"
  done
  for name in $(admin iam list-role-policies --role-name "$SRC_ROLE" --query 'PolicyNames[]' --output text); do
    admin iam put-role-policy --role-name "$CORE_ROLE" --policy-name "$name" \
      --policy-document "$(admin iam get-role-policy --role-name "$SRC_ROLE" --policy-name "$name" --query PolicyDocument --output json)"
  done
fi
admin iam put-role-policy --role-name "$CORE_ROLE" --policy-name honeytoken-poller --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {\"Effect\": \"Allow\", \"Action\": \"sts:AssumeRole\", \"Resource\": \"arn:aws:iam::$HT:role/$READER_ROLE\"},
    {\"Effect\": \"Allow\", \"Action\": \"sns:Publish\", \"Resource\": \"$TOPIC_ARN\"}
  ]}"
admin iam get-instance-profile --instance-profile-name "$CORE_ROLE" >/dev/null 2>&1 ||
  admin iam create-instance-profile --instance-profile-name "$CORE_ROLE" >/dev/null
if [[ $(admin iam get-instance-profile --instance-profile-name "$CORE_ROLE" --query 'InstanceProfile.Roles | length(@)' --output text) == 0 ]]; then
  admin iam add-role-to-instance-profile --instance-profile-name "$CORE_ROLE" --role-name "$CORE_ROLE"
fi
if [[ "${CUR_PROFILE_ARN##*/}" != "$CORE_ROLE" ]]; then
  echo "[*] Swapping chronos-soc-core instance profile ${CUR_PROFILE_ARN##*/} -> $CORE_ROLE"
  retry 9 admin ec2 replace-iam-instance-profile-association --association-id "$ASSOC_ID" \
    --iam-instance-profile "Name=$CORE_ROLE" >/dev/null
fi
echo "[+] chronos-soc-core runs as $CORE_ROLE; alerts -> $TOPIC_ARN"

# ---- Member account, via OrganizationAccountAccessRole -------------------------------------------------------
cleanup() { admin iam delete-user-policy --user-name "$OPER_USER" --policy-name "$TEMP_POLICY" 2>/dev/null || true; }
trap cleanup EXIT
admin iam put-user-policy --user-name "$OPER_USER" --policy-name "$TEMP_POLICY" --policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"arn:aws:iam::$HT:role/OrganizationAccountAccessRole\"}]}"
creds=""
for _ in $(seq 1 30); do
  creds=$(oper sts assume-role --role-arn "arn:aws:iam::$HT:role/OrganizationAccountAccessRole" \
    --role-session-name chronos-honeytoken-provisioning \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text 2>/dev/null) && break
  sleep 10
done
[[ -n "$creds" ]] || { echo "[-] Could not assume OrganizationAccountAccessRole in $HT" >&2; exit 1; }
read -r HT_AK HT_SK HT_ST <<<"$creds"
ht() {
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE AWS_ACCESS_KEY_ID="$HT_AK" AWS_SECRET_ACCESS_KEY="$HT_SK" \
    AWS_SESSION_TOKEN="$HT_ST" aws --region us-east-1 "$@"
}
withkey() {  # withkey <key-id> <secret> <aws args...>: act as a bait key
  local k="$1" s="$2"; shift 2
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID="$k" AWS_SECRET_ACCESS_KEY="$s" \
    aws --region us-east-1 "$@"
}

DENY_ALL='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
umask 077
NEW_ENV=$(mktemp)
echo "# Generated by scripts/honeytokens-provision.sh $(date -u +%Y-%m-%dT%H:%MZ). Gitignored: never commit." >"$NEW_ENV"
for pair in $BAITS; do
  bait="${pair%%:*}" user="${pair#*:}"
  ht iam get-user --user-name "$user" >/dev/null 2>&1 || ht iam create-user --user-name "$user" >/dev/null
  ht iam put-user-policy --user-name "$user" --policy-name deny-all --policy-document "$DENY_ALL"
  [[ $(ht iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies | length(@)' --output text) == 0 &&
     $(ht iam list-groups-for-user --user-name "$user" --query 'Groups | length(@)' --output text) == 0 ]] ||
    { echo "[-] $user has attached policies or groups; refusing to continue" >&2; exit 1; }
  key_id=$(envval "HONEYTOKEN_${bait}_AWS_KEY_ID") secret=$(envval "HONEYTOKEN_${bait}_AWS_SECRET")
  existing=$(ht iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
  if [[ -z "$key_id" || -z "$secret" || " $existing " != *" $key_id "* ]]; then
    for old in $existing; do ht iam delete-access-key --user-name "$user" --access-key-id "$old"; done
    read -r key_id secret < <(ht iam create-access-key --user-name "$user" \
      --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
    echo "[+] $bait: new key $key_id for $user"
  else
    echo "[+] $bait: keeping key $key_id for $user"
  fi
  printf 'HONEYTOKEN_%s_AWS_KEY_ID=%s\nHONEYTOKEN_%s_AWS_SECRET=%s\n' "$bait" "$key_id" "$bait" "$secret" >>"$NEW_ENV"
done

TRUST="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::$MGMT:role/$CORE_ROLE\"},\"Action\":\"sts:AssumeRole\"}]}"
if ht iam get-role --role-name "$READER_ROLE" >/dev/null 2>&1; then
  ht iam update-assume-role-policy --role-name "$READER_ROLE" --policy-document "$TRUST"
else
  retry 9 ht iam create-role --role-name "$READER_ROLE" --assume-role-policy-document "$TRUST" \
    --description "Chronos core honeytoken poller: read CloudTrail event history" >/dev/null
fi
ht iam put-role-policy --role-name "$READER_ROLE" --policy-name read-event-history --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudtrail:LookupEvents","ec2:DescribeRegions"],"Resource":"*"}]}'
printf 'HONEYTOKEN_READER_ROLE_ARN=arn:aws:iam::%s:role/%s\nHONEYTOKEN_ALERT_TOPIC_ARN=%s\n' "$HT" "$READER_ROLE" "$TOPIC_ARN" >>"$NEW_ENV"
mv "$NEW_ENV" "$OUT"
chmod 600 "$OUT"
echo "[+] Wrote $OUT"

# ---- Verify every bait key is inert ----------------------------------------------------------------------------
# These calls are themselves honeytoken use from this Mac: run the findings report with --exclude-ip <your IP>.
echo "[*] Verifying the bait keys can authenticate but do nothing (new keys take a few seconds to work)"
for pair in $BAITS; do
  bait="${pair%%:*}"
  key_id=$(envval "HONEYTOKEN_${bait}_AWS_KEY_ID") secret=$(envval "HONEYTOKEN_${bait}_AWS_SECRET")
  arn=$(retry 6 withkey "$key_id" "$secret" sts get-caller-identity --query Arn --output text)
  if out=$(withkey "$key_id" "$secret" s3api list-buckets 2>&1); then
    echo "[-] $bait key ($arn) could list S3 buckets: STOP and investigate" >&2; exit 1
  fi
  grep -q AccessDenied <<<"$out" || { echo "[-] $bait: unexpected error: $out" >&2; exit 1; }
  echo "[+] $bait: $arn authenticates, s3:ListAllMyBuckets denied"
done
echo "[+] Done. Next: scripts/deploy.sh core && scripts/deploy.sh sensor"
