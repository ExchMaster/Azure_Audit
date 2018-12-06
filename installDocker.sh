curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
systemctl enable docker
systemctl start docker
docker run -d -e keyVaultName=jaiKV1 Azure_Audit