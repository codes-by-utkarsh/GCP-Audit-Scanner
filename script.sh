#!/usr/bin/env bash

# =====================================================================================
# ENTERPRISE GCP SECURITY AUDIT FRAMEWORK (SOC2 ALIGNED - HARDENED EDITION)
# =====================================================================================

set +e
set +u
set +o pipefail

export DEBIAN_FRONTEND=noninteractive

trap 'echo "[!] Non-fatal error occurred, continuing..."' ERR

PROJECT_ID="${1:-}"

if [[ -z "$PROJECT_ID" ]]; then
    echo "[!] Usage: $0 <PROJECT_ID>"
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

BASE_DIR="gcp_audit_${PROJECT_ID}_${TIMESTAMP}"

mkdir -p "$BASE_DIR"/{
    iam,
    compute,
    networking,
    storage,
    kubernetes,
    cloudrun,
    cloudfunctions,
    secrets,
    artifacts,
    oauth,
    exposure,
    prowler,
    trivy,
    logs
}

ERROR_LOG="$BASE_DIR/logs/errors.log"

touch "$ERROR_LOG"

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
# TIMEOUT WRAPPER
# =====================================================================================

timeout_cmd() {

    timeout 900 "$@"

    EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 124 ]]; then

        echo "$(date) | TIMEOUT | $*" >> "$ERROR_LOG"

    fi

    return 0
}

# =====================================================================================
# SAFE EXECUTION
# =====================================================================================

run_cmd() {

    DESC="$1"
    shift

    echo
    echo "[+] $DESC"
    echo "[*] Running: $*"
    echo

    timeout_cmd "$@"

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
coreutils

# =====================================================================================
# INSTALL GCLOUD
# =====================================================================================

if ! command -v gcloud >/dev/null 2>&1; then

    run_cmd \
    "Install GCloud SDK" \
    bash -c \
    "curl -s https://sdk.cloud.google.com | bash"

    export PATH="$PATH:$HOME/google-cloud-sdk/bin"

fi

# =====================================================================================
# INSTALL KUBECTL
# =====================================================================================

if ! command -v kubectl >/dev/null 2>&1; then

    run_cmd \
    "Install kubectl" \
    gcloud components install kubectl --quiet

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
"jq '.bindings[] | select(.role | test(\"owner|editor|admin|iam|security|resourcemanager\"; \"i\"))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/high_priv_roles.json'"

run_cmd \
"Public IAM exposure detection" \
bash -c \
"jq '.bindings[] | select((.members[]? | contains(\"allUsers\")) or (.members[]? | contains(\"allAuthenticatedUsers\")))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/public_bindings.json'"

fi

# =====================================================================================
# SERVICE ACCOUNTS
# =====================================================================================

run_cmd \
"Service account enumeration" \
bash -c \
"gcloud iam service-accounts list --format=json > '$BASE_DIR/iam/service_accounts.json'"

if [[ -s "$BASE_DIR/iam/service_accounts.json" ]]; then

while read -r sa; do

    [[ -z "$sa" ]] && continue

    SAFE_NAME=$(echo "$sa" | tr '@.' '_')

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

done < <(
    jq -r '.[].email' \
    "$BASE_DIR/iam/service_accounts.json" 2>/dev/null
)

fi

# =====================================================================================
# COMPUTE INSTANCES
# =====================================================================================

run_cmd \
"Compute instance enumeration" \
bash -c \
"gcloud compute instances list --format=json > '$BASE_DIR/compute/instances.json'"

if [[ -s "$BASE_DIR/compute/instances.json" ]]; then

run_cmd \
"External IP analysis" \
bash -c \
"jq '[ .[] | {name: .name, externalIPs: [ .networkInterfaces[]?.accessConfigs[]?.natIP ]}]' '$BASE_DIR/compute/instances.json' > '$BASE_DIR/exposure/external_ips.json'"

run_cmd \
"OAuth scope extraction" \
bash -c \
"jq '[ .[] | {instance: .name, scopes: [ .serviceAccounts[]?.scopes[] ]}]' '$BASE_DIR/compute/instances.json' > '$BASE_DIR/oauth/oauth_scopes.json'"

fi

# =====================================================================================
# FIREWALL RULES
# =====================================================================================

run_cmd \
"Firewall enumeration" \
bash -c \
"gcloud compute firewall-rules list --format=json > '$BASE_DIR/networking/firewall_rules.json'"

# =====================================================================================
# STORAGE
# =====================================================================================

run_cmd \
"Bucket enumeration" \
bash -c \
"gcloud storage buckets list --format=json > '$BASE_DIR/storage/buckets.json'"

if [[ -s "$BASE_DIR/storage/buckets.json" ]]; then

while read -r bucket; do

    [[ -z "$bucket" ]] && continue

    SAFE_NAME=$(echo "$bucket" | tr '/:' '_')

    run_cmd \
    "Bucket IAM extraction: $bucket" \
    bash -c \
    "gcloud storage buckets get-iam-policy '$bucket' \
    --format=json \
    > '$BASE_DIR/storage/${SAFE_NAME}_iam.json'"

done < <(
    jq -r '.[].name' \
    "$BASE_DIR/storage/buckets.json" 2>/dev/null
)

fi

# =====================================================================================
# GKE CLUSTERS
# =====================================================================================

run_cmd \
"GKE cluster enumeration" \
bash -c \
"gcloud container clusters list --format=json > '$BASE_DIR/kubernetes/clusters.json'"

# =====================================================================================
# GKE RBAC & TRIVY KUBERNETES SCAN
# =====================================================================================

if [[ -s "$BASE_DIR/kubernetes/clusters.json" ]]; then

mkdir -p "$BASE_DIR/trivy/k8s"

while read -r cluster; do

    [[ -z "$cluster" ]] && continue

    LOCATION=$(gcloud container clusters list \
    --filter="name=$cluster" \
    --format="value(location)" \
    2>/dev/null | head -n1)

    [[ -z "$LOCATION" ]] && continue

    run_cmd \
    "Fetch credentials for $cluster" \
    gcloud container clusters get-credentials \
    "$cluster" \
    --location "$LOCATION"

    run_cmd \
    "ClusterRoleBindings extraction: $cluster" \
    bash -c \
    "kubectl --request-timeout=30s get clusterrolebindings -o yaml > '$BASE_DIR/kubernetes/${cluster}_clusterrolebindings.yaml'"

    run_cmd \
    "RBAC extraction: $cluster" \
    bash -c \
    "kubectl --request-timeout=30s get roles,rolebindings -A -o yaml > '$BASE_DIR/kubernetes/${cluster}_rbac.yaml'"

    run_cmd \
    "Trivy Kubernetes summary scan: $cluster" \
    bash -c \
    "trivy k8s \
    --report summary \
    --timeout 15m \
    cluster \
    > '$BASE_DIR/trivy/k8s/${cluster}_summary.txt'"

    run_cmd \
    "Trivy Kubernetes JSON scan: $cluster" \
    bash -c \
    "trivy k8s \
    --report all \
    --format json \
    --timeout 15m \
    cluster \
    > '$BASE_DIR/trivy/k8s/${cluster}_full.json'"

done < <(
    jq -r '.[].name' \
    "$BASE_DIR/kubernetes/clusters.json" 2>/dev/null
)

fi

# =====================================================================================
# CLOUD FUNCTIONS
# =====================================================================================

run_cmd \
"Cloud Functions enumeration" \
bash -c \
"gcloud functions list --format=json > '$BASE_DIR/cloudfunctions/functions.json'"

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

    SAFE_NAME=$(echo "$service" | tr '/:' '_')

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

while read -r secret; do

    [[ -z "$secret" ]] && continue

    SAFE_NAME=$(basename "$secret")

    run_cmd \
    "Secret IAM extraction: $SAFE_NAME" \
    bash -c \
    "gcloud secrets get-iam-policy '$SAFE_NAME' \
    --format=json \
    > '$BASE_DIR/secrets/${SAFE_NAME}_iam.json'"

done < <(
    jq -r '.[].name' \
    "$BASE_DIR/secrets/secrets.json" 2>/dev/null
)

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

while read -r repo format location; do

    [[ -z "$repo" ]] && continue

    if [[ "$format" != "DOCKER" ]]; then
        continue
    fi

    run_cmd \
    "Artifact image enumeration: $repo" \
    bash -c \
    "gcloud artifacts docker images list '$repo' \
    --include-tags \
    --format='value(package)' \
    >> '$IMAGE_FILE'"

done < <(

    jq -r '
    .[]
    | [
        .name,
        .format,
        .location
      ]
    | @tsv
    ' "$BASE_DIR/artifacts/repositories.json" 2>/dev/null

)

fi

sort -u "$IMAGE_FILE" -o "$IMAGE_FILE"

# =====================================================================================
# TRIVY FILESYSTEM SCAN
# =====================================================================================

run_cmd \
"Trivy filesystem scan" \
bash -c \
"trivy fs \
--timeout 15m \
. \
--scanners vuln,secret,misconfig \
--format json \
--output '$BASE_DIR/trivy/filesystem_scan.json'"

# =====================================================================================
# TRIVY IMAGE SCANS
# =====================================================================================

if [[ -s "$IMAGE_FILE" ]]; then

while read -r image; do

    [[ -z "$image" ]] && continue

    SAFE_NAME=$(echo "$image" | tr '/:' '_')

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
--project-id '$PROJECT_ID' \
--compliance soc2_gcp \
--output-directory '$BASE_DIR/prowler' \
--output-formats json csv html"

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
echo "======================================================================"
