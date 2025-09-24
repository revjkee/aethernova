# Политика доступа к ключу в Vault Transit Engine
path "transit/encrypt/service-tokens-key" {
  capabilities = ["update"]
}

path "transit/decrypt/service-tokens-key" {
  capabilities = ["update"]
}

path "transit/rewrap/service-tokens-key" {
  capabilities = ["update"]
}

path "transit/keys/service-tokens-key" {
  capabilities = ["read"]
}

path "sys/key-status/service-tokens-key" {
  capabilities = ["read"]
}

# Ограничение на чтение общих политик для безопасности
path "sys/policies/acl" {
  capabilities = ["list"]
}
