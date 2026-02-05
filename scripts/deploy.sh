#!/bin/bash

# AegisFlow AI Deployment Script for Google Cloud

set -e

# 環境変数の確認
if [ -z "$GCP_PROJECT_ID" ]; then
    echo "Error: GCP_PROJECT_ID environment variable is not set"
    exit 1
fi

if [ -z "$GCP_REGION" ]; then
    export GCP_REGION="us-central1"
    echo "Using default region: $GCP_REGION"
fi

echo "========================================"
echo "AegisFlow AI - Google Cloud Deployment"
echo "========================================"
echo "Project ID: $GCP_PROJECT_ID"
echo "Region: $GCP_REGION"
echo ""

# Google Cloud APIs の有効化
echo "[1/7] Enabling required Google Cloud APIs..."
gcloud services enable \
    aiplatform.googleapis.com \
    cloudfunctions.googleapis.com \
    cloudrun.googleapis.com \
    firestore.googleapis.com \
    pubsub.googleapis.com \
    artifactregistry.googleapis.com \
    --project=$GCP_PROJECT_ID

# Artifact Registry リポジトリの作成
echo "[2/7] Creating Artifact Registry repository..."
gcloud artifacts repositories create aegisflow \
    --repository-format=docker \
    --location=$GCP_REGION \
    --description="AegisFlow AI container images" \
    --project=$GCP_PROJECT_ID \
    || echo "Repository already exists, continuing..."

# Firestore データベースの初期化
echo "[3/7] Initializing Firestore database..."
gcloud firestore databases create \
    --location=$GCP_REGION \
    --project=$GCP_PROJECT_ID \
    || echo "Firestore database already exists, continuing..."

# Pub/Sub トピックの作成
echo "[4/7] Creating Pub/Sub topics..."
gcloud pubsub topics create aegisflow-security-events --project=$GCP_PROJECT_ID || true
gcloud pubsub topics create aegisflow-feedback-loop --project=$GCP_PROJECT_ID || true
gcloud pubsub topics create aegisflow-policy-updates --project=$GCP_PROJECT_ID || true
gcloud pubsub topics create aegisflow-red-team-findings --project=$GCP_PROJECT_ID || true

# サービスアカウントの作成
echo "[5/7] Creating service account..."
gcloud iam service-accounts create aegisflow-gatekeeper \
    --description="AegisFlow Gatekeeper service account" \
    --display-name="AegisFlow Gatekeeper" \
    --project=$GCP_PROJECT_ID \
    || echo "Service account already exists, continuing..."

# IAM権限の付与
echo "[6/7] Granting IAM permissions..."
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:aegisflow-gatekeeper@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:aegisflow-gatekeeper@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/datastore.user"

gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:aegisflow-gatekeeper@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/pubsub.publisher"

# Dockerイメージのビルドとプッシュ
echo "[7/7] Building and pushing Docker image..."
IMAGE_NAME="$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/aegisflow/gatekeeper:latest"

docker build -t $IMAGE_NAME -f deployment/cloud_run/Dockerfile .
docker push $IMAGE_NAME

# Cloud Runへのデプロイ
echo "Deploying to Cloud Run..."
gcloud run deploy aegisflow-gatekeeper \
    --image=$IMAGE_NAME \
    --platform=managed \
    --region=$GCP_REGION \
    --allow-unauthenticated \
    --service-account=aegisflow-gatekeeper@$GCP_PROJECT_ID.iam.gserviceaccount.com \
    --min-instances=1 \
    --max-instances=100 \
    --cpu=2 \
    --memory=4Gi \
    --timeout=300 \
    --set-env-vars="GCP_PROJECT_ID=$GCP_PROJECT_ID,GCP_LOCATION=$GCP_REGION" \
    --project=$GCP_PROJECT_ID

# デプロイ完了
SERVICE_URL=$(gcloud run services describe aegisflow-gatekeeper \
    --region=$GCP_REGION \
    --project=$GCP_PROJECT_ID \
    --format='value(status.url)')

echo ""
echo "========================================"
echo "Deployment completed successfully!"
echo "========================================"
echo "Service URL: $SERVICE_URL"
echo ""
echo "Test the deployment:"
echo "curl $SERVICE_URL/health"
echo ""
