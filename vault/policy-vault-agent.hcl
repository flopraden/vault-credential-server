auto_auth {
  method {
    type = "approle"

    config = {
      role_id_file_path = "role-id"
      secret_id_file_path = "secret-id"
      secret_id_response_wrapping_path = "auth/approle/role/example/secret-id"
      # credential directory is read-only
      remove_secret_id_file_after_reading = false
    }
  }
}

template_config {
  exit_on_retry_failure = true
}

template {
  contents = "{{- with secret \"secret/applications/example\" }}{{ .Data.foo }}{{- end }}"
  destination = "/run/example/secret"
  perms = "0600"
}