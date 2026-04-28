#!/usr/bin/env bash

# =====================================================================================
# HARDENED ENTERPRISE GCP SECURITY AUDIT FRAMEWORK (SOC2 ALIGNED)
# =====================================================================================

set +e
set +u
set +o pipefail

export DEBIAN_FRONTEND=noninteractive

PROJECT_ID="${1:-}"

if [[ -z "$PROJECT_ID" ]]; then
    echo "[!] Usage: $0 <PROJECT_ID>"
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BASE_DIR="gcp_audit_${PROJECT_ID}_${TIMESTAMP}"

# =====================================================================================
# SAFE DIRECTORY CREATION
# =====================================================================================

mkdir -p \
"$BASE_DIR/iam" \
"$BASE_DIR/compute" \
"$BASE_DIR/networking" \
"$BASE_DIR/storage" \
"$BASE_DIR/kubernetes" \
"$BASE_DIR/cloudrun" \
"$BASE_DIR/cloudfunctions" \
"$BASE_DIR/secrets" \
"$BASE_DIR/artifacts" \
"$BASE_DIR/oauth" \
"$BASE_DIR/exposure" \
"$BASE_DIR/prowler" \
"$BASE_DIR/trivy" \
"$BASE_DIR/trivy/k8s" \
"$BASE_DIR/logs"

ERROR_LOG="$BASE_DIR/logs/errors.log"
COMMAND_LOG="$BASE_DIR/logs/commands.log"

touch "$ERROR_LOG"
touch "$COMMAND_LOG"

# =====================================================================================
# LOGGING
# =====================================================================================

log() {

    echo
    echo "================================================================"
    echo "[+] $1"
    echo "================================================================"
    echo

}

# =====================================================================================
# SANITIZATION
# =====================================================================================

safe_name() {

    echo "$1" | tr '/:@ ' '_' | tr -cd '[:alnum:]_.-'

}

# =====================================================================================
# RETRY WRAPPER
# =====================================================================================

retry_cmd() {

    local retries=3
    local delay=5

    for ((i=1; i<=retries; i++)); do

        "$@"

        EXIT_CODE=$?

        if [[ $EXIT_CODE -eq 0 ]]; then
            return 0
        fi

        sleep "$delay"

    done

    return $EXIT_CODE

}

# =====================================================================================
# TIMEOUT WRAPPER
# =====================================================================================

timeout_cmd() {

    timeout 900 "$@"

    EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 124 ]]; then

        echo "$(date) | TIMEOUT | $*" >> "$ERROR_LOG"

    fi

    return $EXIT_CODE

}

# =====================================================================================
# SAFE EXECUTION
# =====================================================================================

run_cmd() {

    DESC="$1"
    shift

    echo "$(date) | $DESC | $*" >> "$COMMAND_LOG"

    echo
    echo "[+] $DESC"
    echo "[*] Running: $*"
    echo

    retry_cmd timeout_cmd "$@"

    EXIT_CODE=$?

    if [[ $EXIT_CODE -ne 0 ]]; then

        echo "[!] FAILED: $DESC"

        echo \
        "$(date) | FAILED | EXIT_CODE=$EXIT_CODE | $DESC | CMD=$*" \
        >> "$ERROR_LOG"

    else

        echo "[+] SUCCESS: $DESC"

    fi

    return 0

}

# =====================================================================================
# INSTALL DEPENDENCIES
# =====================================================================================

log "Installing dependencies"

run_cmd \
"APT Update" \
sudo apt-get update -y

run_cmd \
"Install dependencies" \
sudo apt-get install -y \
curl \
wget \
jq \
unzip \
python3 \
python3-pip \
docker.io \
apt-transport-https \
ca-certificates \
gnupg \
lsb-release \
coreutils \
kubectl

# =====================================================================================
# INSTALL GCLOUD SDK
# =====================================================================================

if ! command -v gcloud >/dev/null 2>&1; then

    run_cmd \
    "Install GCloud SDK" \
    bash -c \
    "curl -s https://sdk.cloud.google.com | bash"

    export PATH="$PATH:$HOME/google-cloud-sdk/bin"

fi

# =====================================================================================
# INSTALL PROWLER
# =====================================================================================

if ! command -v prowler >/dev/null 2>&1; then

    run_cmd \
    "Upgrade pip" \
    python3 -m pip install --upgrade pip

    run_cmd \
    "Install Prowler" \
    python3 -m pip install prowler

fi

# =====================================================================================
# INSTALL TRIVY
# =====================================================================================

if ! command -v trivy >/dev/null 2>&1; then

    run_cmd \
    "Install Trivy" \
    bash -c \
    "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin"

fi

# =====================================================================================
# AUTHENTICATION
# =====================================================================================

log "Checking authentication"

ACTIVE_ACCOUNT=$(gcloud auth list \
--filter=status:ACTIVE \
--format="value(account)" 2>/dev/null)

if [[ -z "$ACTIVE_ACCOUNT" ]]; then

    run_cmd \
    "GCloud Login" \
    gcloud auth login --no-launch-browser

    run_cmd \
    "Application Default Login" \
    gcloud auth application-default login --no-launch-browser

fi

run_cmd \
"Validate credentials" \
gcloud auth print-access-token

# =====================================================================================
# SET PROJECT
# =====================================================================================

run_cmd \
"Set active project" \
gcloud config set project "$PROJECT_ID"

# =====================================================================================
# VERIFY ACCESS
# =====================================================================================

run_cmd \
"Verify project access" \
bash -c \
"gcloud projects describe '$PROJECT_ID' > '$BASE_DIR/logs/project.json'"

# =====================================================================================
# ENABLED APIS
# =====================================================================================

run_cmd \
"Enumerate enabled APIs" \
bash -c \
"gcloud services list --enabled --format=json > '$BASE_DIR/logs/enabled_apis.json'"

# =====================================================================================
# IAM ENUMERATION
# =====================================================================================

run_cmd \
"IAM policy extraction" \
bash -c \
"gcloud projects get-iam-policy '$PROJECT_ID' --format=json > '$BASE_DIR/iam/project_iam.json'"

if [[ -s "$BASE_DIR/iam/project_iam.json" ]]; then

run_cmd \
"High privilege role detection" \
bash -c \
"jq '.bindings[]? | select(.role | test(\"owner|editor|admin|iam|security|resourcemanager\"; \"i\"))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/high_priv_roles.json'"

run_cmd \
"Public IAM exposure detection" \
bash -c \
"jq '.bindings[]? | select((.members[]? | contains(\"allUsers\")) or (.members[]? | contains(\"allAuthenticatedUsers\")))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/public_bindings.json'"

fi

# =====================================================================================
# SERVICE ACCOUNTS
# =====================================================================================

run_cmd \
"Service account enumeration" \
bash -c \
"gcloud iam service-accounts list --format=json > '$BASE_DIR/iam/service_accounts.json'"

if [[ -s "$BASE_DIR/iam/service_accounts.json" ]]; then

jq -r '.[].email // empty' \
"$BASE_DIR/iam/service_accounts.json" 2>/dev/null | while read -r sa; do

    [[ -z "$sa" ]] && continue

    SAFE_NAME=$(safe_name "$sa")

    run_cmd \
    "Service account key enumeration: $sa" \
    bash -c \
    "gcloud iam service-accounts keys list \
    --iam-account '$sa' \
    --format=json \
    > '$BASE_DIR/iam/${SAFE_NAME}_keys.json'"

    run_cmd \
    "Workload identity extraction: $sa" \
    bash -c \
    "gcloud iam service-accounts get-iam-policy '$sa' \
    --format=json \
    > '$BASE_DIR/iam/workload_identity_${SAFE_NAME}.json'"

done

fi

# =====================================================================================
# COMPUTE
# =====================================================================================

run_cmd \
"Compute instance enumeration" \
bash -c \
"gcloud compute instances list --format=json > '$BASE_DIR/compute/instances.json'"

if [[ -s "$BASE_DIR/compute/instances.json" ]]; then

run_cmd \
"External IP analysis" \
bash -c \
"jq '[ .[]? | {name: .name, externalIPs: [ .networkInterfaces[]?.accessConfigs[]?.natIP ]}]' '$BASE_DIR/compute/instances.json' > '$BASE_DIR/exposure/external_ips.json'"

run_cmd \
"OAuth scope extraction" \
bash -c \
"jq '[ .[]? | {instance: .name, scopes: [ .serviceAccounts[]?.scopes[] ]}]' '$BASE_DIR/compute/instances.json' > '$BASE_DIR/oauth/oauth_scopes.json'"

fi

# =====================================================================================
# NETWORKING
# =====================================================================================

run_cmd \
"Firewall enumeration" \
bash -c \
"gcloud compute firewall-rules list --format=json > '$BASE_DIR/networking/firewall_rules.json'"

run_cmd \
"VPC enumeration" \
bash -c \
"gcloud compute networks list --format=json > '$BASE_DIR/networking/networks.json'"

# =====================================================================================
# STORAGE
# =====================================================================================

run_cmd \
"Bucket enumeration" \
bash -c \
"gcloud storage buckets list --format=json > '$BASE_DIR/storage/buckets.json'"

if [[ -s "$BASE_DIR/storage/buckets.json" ]]; then

jq -r '.[].name // empty' \
"$BASE_DIR/storage/buckets.json" 2>/dev/null | while read -r bucket; do

    [[ -z "$bucket" ]] && continue

    SAFE_NAME=$(safe_name "$bucket")

    run_cmd \
    "Bucket IAM extraction: $bucket" \
    bash -c \
    "gcloud storage buckets get-iam-policy '$bucket' \
    --format=json \
    > '$BASE_DIR/storage/${SAFE_NAME}_iam.json'"

done

fi

# =====================================================================================
# GKE ENUMERATION
# =====================================================================================

run_cmd \
"GKE cluster enumeration" \
bash -c \
"gcloud container clusters list --format=json > '$BASE_DIR/kubernetes/clusters.json'"

# =====================================================================================
# GKE RBAC + TRIVY SCANS
# =====================================================================================

if [[ -s "$BASE_DIR/kubernetes/clusters.json" ]]; then

jq -c '.[]' "$BASE_DIR/kubernetes/clusters.json" 2>/dev/null | while read -r cluster_json; do

    cluster=$(echo "$cluster_json" | jq -r '.name // empty')
    location=$(echo "$cluster_json" | jq -r '.location // empty')

    [[ -z "$cluster" ]] && continue
    [[ -z "$location" ]] && continue

    SAFE_CLUSTER=$(safe_name "$cluster")

    run_cmd \
    "Fetch credentials for $cluster" \
    gcloud container clusters get-credentials \
    "$cluster" \
    --location "$location"

    run_cmd \
    "ClusterRoleBindings extraction: $cluster" \
    bash -c \
    "kubectl --request-timeout=30s get clusterrolebindings -o yaml > '$BASE_DIR/kubernetes/${SAFE_CLUSTER}_clusterrolebindings.yaml'"

    run_cmd \
    "RBAC extraction: $cluster" \
    bash -c \
    "kubectl --request-timeout=30s get roles,rolebindings -A -o yaml > '$BASE_DIR/kubernetes/${SAFE_CLUSTER}_rbac.yaml'"

    run_cmd \
    "Trivy Kubernetes summary scan: $cluster" \
    bash -c \
    "trivy k8s cluster \
    --report summary \
    --timeout 15m \
    > '$BASE_DIR/trivy/k8s/${SAFE_CLUSTER}_summary.txt'"

    run_cmd \
    "Trivy Kubernetes JSON scan: $cluster" \
    bash -c \
    "trivy k8s cluster \
    --report all \
    --format json \
    --timeout 15m \
    > '$BASE_DIR/trivy/k8s/${SAFE_CLUSTER}_full.json'"

done

fi

# =====================================================================================
# CLOUD FUNCTIONS
# =====================================================================================

run_cmd \
"Cloud Functions Gen1 enumeration" \
bash -c \
"gcloud functions list --format=json > '$BASE_DIR/cloudfunctions/functions_gen1.json'"

run_cmd \
"Cloud Functions Gen2 enumeration" \
bash -c \
"gcloud functions list --gen2 --format=json > '$BASE_DIR/cloudfunctions/functions_gen2.json'"

# =====================================================================================
# CLOUD RUN
# =====================================================================================

run_cmd \
"Cloud Run enumeration" \
bash -c \
"gcloud run services list \
--platform managed \
--format='csv[no-heading](name,region)' \
> '$BASE_DIR/cloudrun/services_with_regions.txt'"

if [[ -s "$BASE_DIR/cloudrun/services_with_regions.txt" ]]; then

while IFS=',' read -r service region; do

    [[ -z "$service" ]] && continue
    [[ -z "$region" ]] && continue

    SAFE_NAME=$(safe_name "$service")

    run_cmd \
    "Cloud Run IAM extraction: $service ($region)" \
    bash -c \
    "gcloud run services get-iam-policy '$service' \
    --region '$region' \
    --format=json \
    > '$BASE_DIR/cloudrun/${SAFE_NAME}_policy.json'"

done < "$BASE_DIR/cloudrun/services_with_regions.txt"

fi

# =====================================================================================
# SECRET MANAGER
# =====================================================================================

run_cmd \
"Secret enumeration" \
bash -c \
"gcloud secrets list --format=json > '$BASE_DIR/secrets/secrets.json'"

if [[ -s "$BASE_DIR/secrets/secrets.json" ]]; then

jq -r '.[].name // empty' \
"$BASE_DIR/secrets/secrets.json" 2>/dev/null | while read -r secret; do

    [[ -z "$secret" ]] && continue

    SECRET_NAME=$(basename "$secret")
    SAFE_NAME=$(safe_name "$SECRET_NAME")

    run_cmd \
    "Secret IAM extraction: $SECRET_NAME" \
    bash -c \
    "gcloud secrets get-iam-policy '$SECRET_NAME' \
    --format=json \
    > '$BASE_DIR/secrets/${SAFE_NAME}_iam.json'"

done

fi

# =====================================================================================
# ARTIFACT REGISTRY
# =====================================================================================

IMAGE_FILE="$BASE_DIR/artifacts/images.txt"

touch "$IMAGE_FILE"

run_cmd \
"Artifact repository enumeration" \
bash -c \
"gcloud artifacts repositories list --format=json > '$BASE_DIR/artifacts/repositories.json'"

if [[ -s "$BASE_DIR/artifacts/repositories.json" ]]; then

jq -c '.[]' "$BASE_DIR/artifacts/repositories.json" 2>/dev/null | while read -r repo_json; do

    repo=$(echo "$repo_json" | jq -r '.name // empty')
    format=$(echo "$repo_json" | jq -r '.format // empty')
    location=$(echo "$repo_json" | jq -r '.location // empty')

    [[ -z "$repo" ]] && continue

    if [[ "$format" != "DOCKER" ]]; then
        continue
    fi

    repo_name=$(basename "$repo")

    run_cmd \
    "Artifact image enumeration: $repo_name" \
    bash -c \
    "gcloud artifacts docker images list \
    '${location}-docker.pkg.dev/${PROJECT_ID}/${repo_name}' \
    --include-tags \
    --format='value(package)' \
    >> '$IMAGE_FILE'"

done

fi

sort -u "$IMAGE_FILE" -o "$IMAGE_FILE"

# =====================================================================================
# TRIVY FILESYSTEM SCAN
# =====================================================================================

SCAN_PATH="${SCAN_PATH:-.}"

run_cmd \
"Trivy filesystem scan" \
bash -c \
"trivy fs \
--timeout 15m \
'$SCAN_PATH' \
--scanners vuln,secret,misconfig \
--format json \
--output '$BASE_DIR/trivy/filesystem_scan.json'"

# =====================================================================================
# TRIVY IMAGE SCANS
# =====================================================================================

if [[ -s "$IMAGE_FILE" ]]; then

while read -r image; do

    [[ -z "$image" ]] && continue

    SAFE_NAME=$(safe_name "$image")

    run_cmd \
    "Trivy image scan: $image" \
    bash -c \
    "trivy image \
    --timeout 15m \
    --scanners vuln,secret,misconfig \
    --format json \
    --output '$BASE_DIR/trivy/images_${SAFE_NAME}.json' \
    '$image'"

done < "$IMAGE_FILE"

fi

# =====================================================================================
# PROWLER SOC2 AUDIT
# =====================================================================================

run_cmd \
"Prowler SOC2 audit" \
bash -c \
"prowler gcp \
--project-ids '$PROJECT_ID' \
--compliance soc2_gcp \
--output-directory '$BASE_DIR/prowler' \
-M json csv html"

# =====================================================================================
# SUMMARY
# =====================================================================================

echo
echo "======================================================================"
echo "                 GCP AUDIT COMPLETED"
echo "======================================================================"
echo
echo "PROJECT:"
echo "  $PROJECT_ID"
echo
echo "OUTPUT:"
echo "  $BASE_DIR"
echo
echo "ERROR LOG:"
echo "  $ERROR_LOG"
echo
echo "COMMAND LOG:"
echo "  $COMMAND_LOG"
echo
echo "======================================================================"
