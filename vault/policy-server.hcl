path "auth/approle/role/APPNAME/role-id"
{
  capabilities = ["read"]
}
path "auth/approle/role/example/secret-id"
{
  capabilities = ["create", "update"]
  # require that the secret-id must be restricted to a list of CIDRs
  required_parameters = ["cidr_list"]
  # require the secret-id to be wrapped
  min_wrapping_ttl = "1s"
  max_wrapping_ttl = "5m"
}