#!/bin/bash
SERVICEACCOUNT_PATH="/var/run/secrets/kubernetes.io/serviceaccount"
KUBECONFIG_PATH="$HOME/.kube"

if [ ! -d "$SERVICEACCOUNT_PATH" ]; then
    echo "Serviceaccount folder does not exist. Creating..."
    mkdir -p "$SERVICEACCOUNT_PATH"
else
    echo "Serviceaccount folder already exists."
fi

if [ ! -d "$KUBECONFIG_PATH" ]; then
    echo "Kubeconfig folder does not exist. Creating..."
    mkdir -p "$KUBECONFIG_PATH"
else
    echo "Kubeconfig folder already exists."
fi

echo "Copying credentials..."

cp "$PWD/cert.pem" "$PWD/key.pem" "$SERVICEACCOUNT_PATH"

#assume the sysadmin has amready set this up, depends heavily on the network setup
#kubectl config set-cluster my-cluster --server=https://example.com --certificate-authority=/path/to/ca.crt

kubectl config set-credentials my-user --client-certificate=$(SERVICE_ACCOUNT_PATH)/cert.pem --client-key=$(SERVICE_ACCOUNT_PATH)/key.pem

kubectl config set-context edgenode@cloud --cluster=$(kubectl config view --output='jsonpath={.clusters[0].name}') --user=edgenode

kubectl config use-context edgenode@cloud

echo "Files copied successfully, attempting to start FEATHER service..."

#assume that sysadmin has pre-loaded the edgenode with this service
sudo systemctl start feather