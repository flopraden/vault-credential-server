mkdir -p /etc/vault-server

read -p "role-id:" role_id
echo -n "${role_id}" > /etc/vault-server/role-id
chmod 444 /etc/vault-server/role-id

read -p "secret-id:" secret_id
systemd-creds encrypt --name=secret-id - /etc/vault-server/secret-id <<<$secret_id
chmod 400 /etc/vault-server/secret-id

read -p "URL to VAULT, for example https://vault.example.com:8200:" vault_addr
echo "VAULT_ADDR=${vault_addr}" > /etc/vault-server/env
