# utxoplugin

### Deployment Process
```
# Create AWS ECR Repository
aws ecr create-repository --repository-name cloudchainsapp/utxoplugin

# Build Dockerfile
docker build -t <account_id>.dkr.ecr.us-east-1.amazonaws.com/cloudchainsapp/utxoplugin .

# Push to ECR
docker push <account_id>.dkr.ecr.us-east-1.amazonaws.com/cloudchainsapp/utxoplugin

# Deploy application to kubernetes
helm install utxoplugin ./utxoplugin -n cc-backend
```
