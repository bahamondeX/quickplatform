#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
PROJECT_ID="caramel-aria-302621"
REGION="us-central1"
SERVICE_NAME="localstack-free"
ARTIFACT_REGISTRY_REPO="localstack-repo"

# Image: LocalStack with persistence
IMAGE_FULL_NAME="gresau/localstack-persist"
IMAGE_TAG="3.4"
IMAGE_NAME="localstack-free"

# LocalStack Configuration
LOCALSTACK_SERVICES="apigateway,sqs,sns,stepfunctions,cloudwatch,cloudwatchlogs,eventbridge,events,certificatemanager,acm,ec2,lambda,s3,cloudformation,cloudwatch,ssm,secretsmanager,kms,iam,ses,transcribeservice,transcribe,dynamodb,kinesis,opensearch,cognito,route53,redshift,kinesis,sts,opensearch"
LOCALSTACK_DEBUG="1"

# Cloud Run Resource Allocation
CLOUD_RUN_CPU="2"
CLOUD_RUN_MEMORY="4Gi"
CLOUD_RUN_CONCURRENCY="1"
CLOUD_RUN_TIMEOUT="900s"

# Persistence Configuration
USE_PERSISTENCE="true"
GCS_BUCKET_NAME="localstack-store"
LOCALSTACK_PERSIST_PATH="/var/lib/localstack-data"

# --- Script Start ---

echo "--- Setting up Google Cloud Project and APIs ---"
gcloud config set project "${PROJECT_ID}"
gcloud config set run/region "${REGION}"

echo "Enabling necessary Google Cloud APIs..."
gcloud services enable \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com \
    --project="${PROJECT_ID}" || true

echo "--- Configuring Artifact Registry ---"
if ! gcloud artifacts repositories describe "${ARTIFACT_REGISTRY_REPO}" --location="${REGION}" --format="value(name)" &>/dev/null; then
    echo "Creating Artifact Registry repository: ${ARTIFACT_REGISTRY_REPO}"
    gcloud artifacts repositories create "${ARTIFACT_REGISTRY_REPO}" \
        --repository-format=docker \
        --location="${REGION}" \
        --description="Docker repository for LocalStack images" \
        --project="${PROJECT_ID}"
else
    echo "Artifact Registry repository ${ARTIFACT_REGISTRY_REPO} already exists."
fi

echo "Authenticating Docker to Artifact Registry..."
gcloud auth configure-docker "${REGION}-docker.pkg.dev"

SOURCE_IMAGE="${IMAGE_FULL_NAME}:${IMAGE_TAG}"
TARGET_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REGISTRY_REPO}/${IMAGE_NAME}:${IMAGE_TAG}"

echo "Pulling Docker image for linux/amd64: ${SOURCE_IMAGE}"
docker pull --platform linux/amd64 "${SOURCE_IMAGE}"

echo "Tagging image for Artifact Registry: ${TARGET_IMAGE}"
docker tag "${SOURCE_IMAGE}" "${TARGET_IMAGE}"

echo "Pushing image to Artifact Registry..."
docker push "${TARGET_IMAGE}"

echo "--- Deploying LocalStack to Google Cloud Run ---"
echo "Deploying Cloud Run service: ${SERVICE_NAME}"

# Start command
DEPLOY_COMMAND=(
    gcloud run deploy "${SERVICE_NAME}"
    --image "${TARGET_IMAGE}"
    --platform managed
    --region "${REGION}"
    --allow-unauthenticated
    --cpu "${CLOUD_RUN_CPU}"
    --memory "${CLOUD_RUN_MEMORY}"
    --concurrency "${CLOUD_RUN_CONCURRENCY}"
    --timeout "${CLOUD_RUN_TIMEOUT}"
    --port 4566
    --project="${PROJECT_ID}"
    --no-cpu-throttling
)

# Construct environment variables string (one flag only)
ENV_VARS="SERVICES=${LOCALSTACK_SERVICES},DEBUG=${LOCALSTACK_DEBUG}"

# Handle persistence configuration
if [ "${USE_PERSISTENCE}" = "true" ] && [ "${IMAGE_FULL_NAME}" = "gresau/localstack-persist" ]; then
    echo "Persistence is ENABLED using ${IMAGE_FULL_NAME}"

    if ! gsutil ls "gs://${GCS_BUCKET_NAME}" &>/dev/null; then
        echo "Creating GCS bucket: gs://${GCS_BUCKET_NAME}"
        gsutil mb -l "${REGION}" "gs://${GCS_BUCKET_NAME}" || { echo "Failed to create bucket."; exit 1; }
    else
        echo "GCS bucket ${GCS_BUCKET_NAME} already exists."
    fi

    ENV_VARS="${ENV_VARS},PERSIST_BASE_DIR=${LOCALSTACK_PERSIST_PATH}"

    DEPLOY_COMMAND+=(
        --add-volume="name=localstack-data-volume,type=cloud-storage,bucket=${GCS_BUCKET_NAME}"
        --add-volume-mount="volume=localstack-data-volume,mount-path=${LOCALSTACK_PERSIST_PATH}"
    )
elif [ "${USE_PERSISTENCE}" = "true" ] && [ "${IMAGE_FULL_NAME}" = "localstack/localstack" ]; then
    echo "WARNING: Official LocalStack image does NOT support free persistence. Ignoring persistence config."
    USE_PERSISTENCE="false"
fi

# Add env vars at the end
DEPLOY_COMMAND+=(
    --set-env-vars "${ENV_VARS}"
)

# Run deployment
"${DEPLOY_COMMAND[@]}"

echo "--- Deployment Complete ---"
CLOUD_RUN_URL=$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --format="value(status.url)")

echo "LocalStack URL: ${CLOUD_RUN_URL}"
echo ""
echo "Set AWS endpoints to interact with it:"
echo "export AWS_ENDPOINT_URL='${CLOUD_RUN_URL}'"
echo "awslocal s3 ls"
echo "awslocal dynamodb list-tables"

if [ "${USE_PERSISTENCE}" = "true" ]; then
    echo "Persistence is ACTIVE at: gs://${GCS_BUCKET_NAME}"
else
    echo "Persistence is DISABLED. Data will be lost on restart."
fi