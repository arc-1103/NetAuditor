ui            = true
api_addr      = "http://vault:8200"
disable_mlock = false

storage "file" {
  path = "/vault/file"
}

# Plain HTTP on the internal Docker network only. Terminate TLS in front of
# Vault (or set tls_cert_file/tls_key_file here) before exposing it anywhere.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
