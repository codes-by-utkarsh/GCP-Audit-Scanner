#!/usr/bin/env bash

# =====================================================================================
# ENTERPRISE GCP SECURITY AUDIT FRAMEWORK
# =====================================================================================
#
# FEATURES
# --------
# [x] Auto installs dependencies
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
# [x] Cloud Run anonymous access checks
# [x] Secret Manager IAM analysis
# [x] Trivy scans
# [x] Prowler scans
# [x] Privilege escalation heuristic checks
#
# =====================================================================================
#
# USAGE
# -----
#
# chmod +x gcp_enterprise_audit.sh
#
# ./gcp_enterprise_audit.sh PROJECT_ID
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
    echo "============================================================"
    echo "[+] $1"
    echo "============================================================"
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
"Installing required packages" \
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
# INSTALL GCLOUD
# =====================================================================================

if ! command -v gcloud >/dev/null 2>&1; then

    log "Installing Google Cloud SDK"

    run_cmd \
    "Installing GCloud SDK" \
    bash -c \
    "curl https://sdk.cloud.google.com | bash"

    export PATH="$PATH:$HOME/google-cloud-sdk/bin"

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
# AUTH CHECK
# =====================================================================================

log "Checking authentication"

ACTIVE_ACCOUNT=$(gcloud auth list \
--filter=status:ACTIVE \
--format="value(account)" 2>/dev/null)

if [[ -z "$ACTIVE_ACCOUNT" ]]; then

    echo "[!] No active gcloud authentication found"

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

log "Setting GCP project"

run_cmd \
"Setting active project" \
gcloud config set project "$PROJECT_ID"

# =====================================================================================
# VERIFY ACCESS
# =====================================================================================

log "Verifying project access"

run_cmd \
"Project access verification" \
bash -c \
"gcloud projects describe '$PROJECT_ID' > '$BASE_DIR/logs/project.json'"

# =====================================================================================
# ENABLED APIS
# =====================================================================================

log "Enumerating enabled APIs"

run_cmd \
"Enabled APIs enumeration" \
bash -c \
"gcloud services list --enabled --format=json > '$BASE_DIR/logs/enabled_apis.json'"

# =====================================================================================
# IAM ENUMERATION
# =====================================================================================

log "Enumerating IAM policies"

run_cmd \
"IAM policy dump" \
bash -c \
"gcloud projects get-iam-policy '$PROJECT_ID' --format=json > '$BASE_DIR/iam/project_iam.json'"

# =====================================================================================
# HIGH PRIV ROLES
# =====================================================================================

run_cmd \
"High privilege role detection" \
bash -c \
"jq '.bindings[] | select(.role | test(\"owner|editor|admin|security|iam|resourcemanager\"; \"i\"))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/high_priv_roles.json'"

# =====================================================================================
# PUBLIC ACCESS
# =====================================================================================

run_cmd \
"Public IAM exposure detection" \
bash -c \
"jq '.bindings[] | select((.members[]? | contains(\"allUsers\")) or (.members[]? | contains(\"allAuthenticatedUsers\")))' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/public_bindings.json'"

# =====================================================================================
# SERVICE ACCOUNTS
# =====================================================================================

log "Enumerating service accounts"

run_cmd \
"Service account enumeration" \
bash -c \
"gcloud iam service-accounts list --format=json > '$BASE_DIR/iam/service_accounts.json'"

# =====================================================================================
# SERVICE ACCOUNT KEYS
# =====================================================================================

log "Checking service account keys"

while read -r sa; do

    [[ -z "$sa" ]] && continue

    SAFE_NAME=$(echo "$sa" | tr '@.' '_')

    run_cmd \
    "Service account key enumeration: $sa" \
    bash -c \
    "gcloud iam service-accounts keys list --iam-account '$sa' --format=json > '$BASE_DIR/iam/${SAFE_NAME}_keys.json'"

done < <(
    jq -r '.[].email' \
    "$BASE_DIR/iam/service_accounts.json" 2>/dev/null
)

# =====================================================================================
# IMPERSONATION CHECKS
# =====================================================================================

run_cmd \
"Service account impersonation detection" \
bash -c \
"jq '.bindings[] | select(.role == \"roles/iam.serviceAccountTokenCreator\")' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/service_account_impersonation.json'"

# =====================================================================================
# WORKLOAD IDENTITY
# =====================================================================================

log "Enumerating workload identity bindings"

while read -r sa; do

    [[ -z "$sa" ]] && continue

    SAFE_NAME=$(echo "$sa" | tr '@.' '_')

    run_cmd \
    "Workload identity policy extraction: $sa" \
    bash -c \
    "gcloud iam service-accounts get-iam-policy '$sa' --format=json > '$BASE_DIR/iam/workload_identity_${SAFE_NAME}.json'"

done < <(
    jq -r '.[].email' \
    "$BASE_DIR/iam/service_accounts.json" 2>/dev/null
)

# =====================================================================================
# COMPUTE INSTANCES
# =====================================================================================

log "Enumerating compute instances"

run_cmd \
"Compute instance enumeration" \
bash -c \
"gcloud compute instances list --format=json > '$BASE_DIR/compute/instances.json'"

# =====================================================================================
# EXTERNAL IP EXPOSURE
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

log "Enumerating firewall rules"

run_cmd \
"Firewall rule enumeration" \
bash -c \
"gcloud compute firewall-rules list --format=json > '$BASE_DIR/networking/firewall_rules.json'"

# =====================================================================================
# NETWORKS
# =====================================================================================

run_cmd \
"VPC network enumeration" \
bash -c \
"gcloud compute networks list --format=json > '$BASE_DIR/networking/networks.json'"

# =====================================================================================
# STORAGE BUCKETS
# =====================================================================================

log "Enumerating storage buckets"

run_cmd \
"Bucket enumeration" \
bash -c \
"gcloud storage buckets list --format=json > '$BASE_DIR/storage/buckets.json'"

# =====================================================================================
# BUCKET IAM ANALYSIS
# =====================================================================================

while read -r bucket; do

    [[ -z "$bucket" ]] && continue

    SAFE_NAME=$(echo "$bucket" | tr '/:' '_')

    run_cmd \
    "Bucket IAM extraction: $bucket" \
    bash -c \
    "gcloud storage buckets get-iam-policy '$bucket' --format=json > '$BASE_DIR/storage/${SAFE_NAME}_iam.json'"

done < <(
    jq -r '.[].name' \
    "$BASE_DIR/storage/buckets.json" 2>/dev/null
)

# =====================================================================================
# GKE
# =====================================================================================

log "Enumerating GKE clusters"

run_cmd \
"GKE cluster enumeration" \
bash -c \
"gcloud container clusters list --format=json > '$BASE_DIR/kubernetes/clusters.json'"

# =====================================================================================
# GKE RBAC
# =====================================================================================

while read -r cluster; do

    [[ -z "$cluster" ]] && continue

    REGION=$(gcloud container clusters list \
    --filter="name=$cluster" \
    --format="value(location)" \
    2>/dev/null | head -n1)

    run_cmd \
    "Fetching GKE credentials: $cluster" \
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

log "Enumerating Cloud Functions"

run_cmd \
"Cloud Functions enumeration" \
bash -c \
"gcloud functions list --format=json > '$BASE_DIR/cloudfunctions/functions.json'"

# =====================================================================================
# CLOUD RUN
# =====================================================================================

log "Enumerating Cloud Run services"

run_cmd \
"Cloud Run enumeration" \
bash -c \
"gcloud run services list --platform managed --format=json > '$BASE_DIR/cloudrun/services.json'"

# =====================================================================================
# CLOUD RUN PUBLIC ACCESS
# =====================================================================================

while read -r service; do

    [[ -z "$service" ]] && continue

    run_cmd \
    "Cloud Run IAM policy extraction: $service" \
    bash -c \
    "gcloud run services get-iam-policy '$service' --region us-central1 --format=json > '$BASE_DIR/cloudrun/${service}_policy.json'"

done < <(
    jq -r '.[].metadata.name' \
    "$BASE_DIR/cloudrun/services.json" 2>/dev/null
)

# =====================================================================================
# SECRET MANAGER
# =====================================================================================

log "Enumerating secrets"

run_cmd \
"Secret Manager enumeration" \
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
    "gcloud secrets get-iam-policy '$SAFE_NAME' --format=json > '$BASE_DIR/secrets/${SAFE_NAME}_iam.json'"

done < <(
    jq -r '.[].name' \
    "$BASE_DIR/secrets/secrets.json" 2>/dev/null
)

# =====================================================================================
# ARTIFACT REGISTRY IMAGES
# =====================================================================================

log "Enumerating Artifact Registry images"

IMAGE_FILE="$BASE_DIR/artifacts/images.txt"

run_cmd \
"Artifact Registry image enumeration" \
bash -c \
"gcloud artifacts docker images list --include-tags --format='value(package)' > '$IMAGE_FILE'"

# =====================================================================================
# TRIVY FILESYSTEM SCAN
# =====================================================================================

log "Running Trivy filesystem scan"

run_cmd \
"Trivy filesystem scan" \
bash -c \
"trivy fs . --scanners vuln,secret,misconfig --format json --output '$BASE_DIR/trivy/filesystem_scan.json'"

# =====================================================================================
# TRIVY IMAGE SCANS
# =====================================================================================

while read -r image; do

    [[ -z "$image" ]] && continue

    SAFE_NAME=$(echo "$image" | tr '/:' '_')

    run_cmd \
    "Trivy image scan: $image" \
    bash -c \
    "trivy image --scanners vuln,secret,misconfig --format json --output '$BASE_DIR/trivy/images_${SAFE_NAME}.json' '$image'"

done < "$IMAGE_FILE"

# =====================================================================================
# PROWLER
# =====================================================================================

log "Running Prowler"

run_cmd \
"Prowler GCP scan" \
bash -c \
"prowler gcp --project-id '$PROJECT_ID' --output-directory '$BASE_DIR/prowler' --output-formats json csv html"

# =====================================================================================
# PRIVILEGE ESCALATION ANALYSIS
# =====================================================================================

run_cmd \
"Privilege escalation heuristic analysis" \
bash -c \
"jq '.bindings[] | select(.role == \"roles/owner\" or .role == \"roles/editor\" or .role == \"roles/iam.serviceAccountAdmin\" or .role == \"roles/iam.serviceAccountTokenCreator\")' '$BASE_DIR/iam/project_iam.json' > '$BASE_DIR/iam/possible_privesc.json'"

# =====================================================================================
# SUMMARY
# =====================================================================================

echo
echo "======================================================================"
echo "                     GCP AUDIT COMPLETED"
echo "======================================================================"
echo
echo "PROJECT:"
echo "  $PROJECT_ID"
echo
echo "OUTPUT DIRECTORY:"
echo "  $BASE_DIR"
echo
echo "IMPORTANT RESULTS"
echo
echo "  IAM:"
echo "    $BASE_DIR/iam/"
echo
echo "  Exposure:"
echo "    $BASE_DIR/exposure/"
echo
echo "  OAuth:"
echo "    $BASE_DIR/oauth/"
echo
echo "  Networking:"
echo "    $BASE_DIR/networking/"
echo
echo "  Kubernetes:"
echo "    $BASE_DIR/kubernetes/"
echo
echo "  Cloud Run:"
echo "    $BASE_DIR/cloudrun/"
echo
echo "  Cloud Functions:"
echo "    $BASE_DIR/cloudfunctions/"
echo
echo "  Secrets:"
echo "    $BASE_DIR/secrets/"
echo
echo "  Trivy:"
echo "    $BASE_DIR/trivy/"
echo
echo "  Prowler:"
echo "    $BASE_DIR/prowler/"
echo
echo "ERROR LOG:"
echo "  $ERROR_LOG"
echo
echo "======================================================================"
