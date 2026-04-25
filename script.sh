#!/usr/bin/env bash

# =====================================================================================
# ENTERPRISE GCP SECURITY AUDIT FRAMEWORK (SOC2 ALIGNED)
# =====================================================================================
#
# FEATURES
# --------
# [x] Auto installs dependencies
# [x] Auto installs kubectl
# [x] Auto installs Prowler
# [x] Auto installs Trivy
# [x] Continues execution even if commands fail
# [x] Logs all errors
# [x] IAM enumeration
# [x] Public exposure detection
# [x] Service account abuse checks
# [x] Service account impersonation detection
# [x] OAuth scope analysis
# [x] Workload Identity analysis
# [x] External IP exposure mapping
# [x] Firewall enumeration
# [x] Bucket IAM analysis
# [x] GKE RBAC extraction
# [x] Cloud Functions analysis
# [x] Dynamic Cloud Run IAM checks
# [x] Secret Manager IAM analysis
# [x] Artifact Registry enumeration fix
# [x] Trivy timeout support
# [x] SOC2 mapped Prowler findings
#
# =====================================================================================

set +e
set +u
set -o pipefail

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
# SAFE EXECUTION WRAPPER
# =====================================================================================

run_cmd() {

    DESC="$1"
    shift

    echo
    echo "[+] $DESC"
    echo "[*] Running: $*"
    echo

    "$@"

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
lsb-release

# =====================================================================================
# INSTALL GCLOUD SDK
# =====================================================================================

if ! command -v gcloud >/dev/null 2>&1; then

    log "Installing Google Cloud SDK"

    run_cmd \
    "Install GCloud SDK" \
    bash -c \
    "curl https://sdk.cloud.google.com | bash"

    export PATH="$PATH:$HOME/google-cloud-sdk/bin"

fi

# =====================================================================================
# INSTALL KUBECTL
# =====================================================================================

if ! command -v kubectl >/dev/null 2>&1; then

    log "Installing kubectl"

    run_cmd \
    "Install kubectl via gcloud" \
    gcloud components install kubectl --quiet

fi

# =====================================================================================
# INSTALL PROWLER
# =====================================================================================

if ! command -v prowler >/dev/null 2>&1; then

    log "Installing Prowler"

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

    log "Installing Trivy"

    run_cmd \
    "Install Trivy" \
    bash -c \
    "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin"

fi

# =====================================================================================
# AUTHENTICATION
# =====================================================================================

log "Checking GCloud authentication"

ACTIVE_ACCOUNT=$(gcloud auth list \
--filter=status:ACTIVE \
--format="value(account)" 2>/dev/null)

if [[ -z "$ACTIVE_ACCOUNT" ]]; then

    run_cmd \
    "GCloud Login" \
    gcloud auth login

    run_cmd \
    "Application Default Login" \
    gcloud auth application-default login

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

# =====================================================================================
# HIGH PRIVILEGE ROLES
# =====================================================================================

run_cmd \
"High privilege role detection" \
bash -c \
"jq '.bindings[] | select(.role | test(\"owner|editor|admin|iam|security|resourcemanager\"; \"i\"))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/high_priv_roles.json'"

# =====================================================================================
# PUBLIC ACCESS CHECKS
# =====================================================================================

run_cmd \
"Public IAM exposure detection" \
bash -c \
"jq '.bindings[] | select((.members[]? | contains(\"allUsers\")) or (.members[]? | contains(\"allAuthenticatedUsers\")))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/public_bindings.json'"

# =====================================================================================
# SERVICE ACCOUNTS
# =====================================================================================

run_cmd \
"Service account enumeration" \
bash -c \
"gcloud iam service-accounts list --format=json > '$BASE_DIR/iam/service_accounts.json'"

# =====================================================================================
# SERVICE ACCOUNT KEYS
# =====================================================================================

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

done < <(
    jq -r '.[].email' \
    "$BASE_DIR/iam/service_accounts.json" 2>/dev/null
)

# =====================================================================================
# SERVICE ACCOUNT IMPERSONATION
# =====================================================================================

run_cmd \
"Service account impersonation detection" \
bash -c \
"jq '.bindings[] | select(.role == \"roles/iam.serviceAccountTokenCreator\")' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/service_account_impersonation.json'"

# =====================================================================================
# WORKLOAD IDENTITY
# =====================================================================================

while read -r sa; do

    [[ -z "$sa" ]] && continue

    SAFE_NAME=$(echo "$sa" | tr '@.' '_')

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

# =====================================================================================
# COMPUTE INSTANCES
# =====================================================================================

run_cmd \
"Compute instance enumeration" \
bash -c \
"gcloud compute instances list --format=json > '$BASE_DIR/compute/instances.json'"

# =====================================================================================
# EXTERNAL IP ANALYSIS
# =====================================================================================

run_cmd \
"External IP exposure analysis" \
bash -c \
"jq '[ .[] | {name: .name, externalIPs: [ .networkInterfaces[]?.accessConfigs[]?.natIP ]}]' '$BASE_DIR/compute/instances.json' > '$BASE_DIR/exposure/external_ips.json'"

# =====================================================================================
# OAUTH SCOPES
# =====================================================================================

run_cmd \
"OAuth scope extraction" \
bash -c \
"jq '[ .[] | {instance: .name, scopes: [ .serviceAccounts[]?.scopes[] ]}]' '$BASE_DIR/compute/instances.json' > '$BASE_DIR/oauth/oauth_scopes.json'"

# =====================================================================================
# FIREWALL RULES
# =====================================================================================

run_cmd \
"Firewall rule enumeration" \
bash -c \
"gcloud compute firewall-rules list --format=json > '$BASE_DIR/networking/firewall_rules.json'"

# =====================================================================================
# NETWORK ENUMERATION
# =====================================================================================

run_cmd \
"VPC enumeration" \
bash -c \
"gcloud compute networks list --format=json > '$BASE_DIR/networking/networks.json'"

# =====================================================================================
# STORAGE BUCKETS
# =====================================================================================

run_cmd \
"Bucket enumeration" \
bash -c \
"gcloud storage buckets list --format=json > '$BASE_DIR/storage/buckets.json'"

# =====================================================================================
# BUCKET IAM
# =====================================================================================

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

# =====================================================================================
# GKE CLUSTERS
# =====================================================================================

run_cmd \
"GKE cluster enumeration" \
bash -c \
"gcloud container clusters list --format=json > '$BASE_DIR/kubernetes/clusters.json'"

# =====================================================================================
# GKE RBAC EXTRACTION
# =====================================================================================

while read -r cluster; do

    [[ -z "$cluster" ]] && continue

    REGION=$(gcloud container clusters list \
    --filter="name=$cluster" \
    --format="value(location)" \
    2>/dev/null | head -n1)

    run_cmd \
    "Fetch credentials for $cluster" \
    gcloud container clusters get-credentials \
    "$cluster" \
    --region "$REGION"

    run_cmd \
    "ClusterRoleBindings extraction: $cluster" \
    bash -c \
    "kubectl get clusterrolebindings -o yaml > '$BASE_DIR/kubernetes/${cluster}_clusterrolebindings.yaml'"

    run_cmd \
    "RBAC extraction: $cluster" \
    bash -c \
    "kubectl get roles,rolebindings -A -o yaml > '$BASE_DIR/kubernetes/${cluster}_rbac.yaml'"

done < <(
    jq -r '.[].name' \
    "$BASE_DIR/kubernetes/clusters.json" 2>/dev/null
)

# =====================================================================================
# CLOUD FUNCTIONS
# =====================================================================================

run_cmd \
"Cloud Functions enumeration" \
bash -c \
"gcloud functions list --format=json > '$BASE_DIR/cloudfunctions/functions.json'"

# =====================================================================================
# CLOUD RUN ENUMERATION WITH REGIONS
# =====================================================================================

run_cmd \
"Cloud Run enumeration with regions" \
bash -c \
"gcloud run services list \
--platform managed \
--format='value(name,region)' \
> '$BASE_DIR/cloudrun/services_with_regions.txt'"

# =====================================================================================
# CLOUD RUN IAM EXTRACTION
# =====================================================================================

while read -r service region; do

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

# =====================================================================================
# SECRET MANAGER
# =====================================================================================

run_cmd \
"Secret enumeration" \
bash -c \
"gcloud secrets list --format=json > '$BASE_DIR/secrets/secrets.json'"

# =====================================================================================
# SECRET IAM
# =====================================================================================

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

# =====================================================================================
# ARTIFACT REGISTRY ENUMERATION FIX
# =====================================================================================

IMAGE_FILE="$BASE_DIR/artifacts/images.txt"
touch "$IMAGE_FILE"

run_cmd \
"Artifact repository enumeration" \
bash -c \
"gcloud artifacts repositories list --format=json > '$BASE_DIR/artifacts/repositories.json'"

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
    ' "$BASE_DIR/artifacts/repositories.json"

)

# =====================================================================================
# TRIVY FILESYSTEM SCAN
# =====================================================================================

run_cmd \
"Trivy filesystem scan" \
bash -c \
"trivy fs . \
--scanners vuln,secret,misconfig \
--format json \
--output '$BASE_DIR/trivy/filesystem_scan.json'"

# =====================================================================================
# TRIVY IMAGE SCANS
# =====================================================================================

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

# =====================================================================================
# PROWLER SOC2 AUDIT
# =====================================================================================

run_cmd \
"Prowler SOC2 GCP audit" \
bash -c \
"prowler gcp \
--project-id '$PROJECT_ID' \
--compliance soc2_gcp \
--output-directory '$BASE_DIR/prowler' \
--output-formats json csv html"

# =====================================================================================
# PRIVILEGE ESCALATION HEURISTICS
# =====================================================================================

run_cmd \
"Privilege escalation analysis" \
bash -c \
"jq '.bindings[] | select(.role == \"roles/owner\" or .role == \"roles/editor\" or .role == \"roles/iam.serviceAccountAdmin\" or .role == \"roles/iam.serviceAccountTokenCreator\")' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/possible_privesc.json'"

# =====================================================================================
# SUMMARY
# =====================================================================================

echo
echo "======================================================================"
echo "                  GCP ENTERPRISE AUDIT COMPLETE"
echo "======================================================================"
echo
echo "PROJECT:"
echo "  $PROJECT_ID"
echo
echo "OUTPUT DIRECTORY:"
echo "  $BASE_DIR"
echo
echo "ERROR LOG:"
echo "  $ERROR_LOG"
echo
echo "SOC2 OUTPUT:"
echo "  $BASE_DIR/prowler/"
echo
echo "======================================================================"
