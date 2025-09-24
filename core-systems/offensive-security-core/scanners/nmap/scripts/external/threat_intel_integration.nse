-- threat_intel_integration.nse
--
-- Универсальный скрипт интеграции с Threat Intelligence сервисами для сбора данных по IP или домену
-- Требуется передавать API ключи для сервисов через аргументы скрипта
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local stdnse = require "stdnse"
local json = require "json"
local https = require "ssl.https"
local ltn12 = require "ltn12"
local url = require "socket.url"

description = [[
Интеграция с несколькими Threat Intelligence сервисами: VirusTotal, AlienVault OTX, AbuseIPDB.
Собирает и агрегирует данные об IP или домене.
]]

author = "TeslaAI Expert"

license = "Same as Nmap -- https://nmap.org/book/man-legal.html"

categories = {"external", "discovery", "safe"}

portrule = function(host)
  return host.ip ~= nil or host.hostnames[1] ~= nil
end

local function query_https(api_url, headers)
  local response_body = {}
  local res, code, response_headers, status = https.request{
    url = api_url,
    headers = headers,
    sink = ltn12.sink.table(response_body),
    protocol = "tlsv1_2"
  }
  if code ~= 200 then
    return nil, "HTTP error: " .. tostring(code)
  end
  local body = table.concat(response_body)
  local data = json.decode(body)
  if not data then
    return nil, "JSON decode error"
  end
  return data, nil
end

local function virus_total_lookup(api_key, query)
  local api_url = "https://www.virustotal.com/api/v3/ip_addresses/" .. url.escape(query)
  local headers = { ["x-apikey"] = api_key, ["User-Agent"] = "Nmap ThreatIntel NSE Script" }
  return query_https(api_url, headers)
end

local function alienvault_otx_lookup(api_key, query)
  local api_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/" .. url.escape(query) .. "/general"
  local headers = { ["X-OTX-API-KEY"] = api_key, ["User-Agent"] = "Nmap ThreatIntel NSE Script" }
  return query_https(api_url, headers)
end

local function abuseipdb_lookup(api_key, query)
  local api_url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" .. url.escape(query)
  local headers = { ["Key"] = api_key, ["Accept"] = "application/json", ["User-Agent"] = "Nmap ThreatIntel NSE Script" }
  return query_https(api_url, headers)
end

action = function(host)
  local ip = host.ip
  local vt_key = stdnse.get_script_args("threat_intel_virustotal_api_key")
  local otx_key = stdnse.get_script_args("threat_intel_alienvault_api_key")
  local abuse_key = stdnse.get_script_args("threat_intel_abuseipdb_api_key")

  if not (vt_key or otx_key or abuse_key) then
    return "Требуется как минимум один API ключ из: threat_intel_virustotal_api_key, threat_intel_alienvault_api_key, threat_intel_abuseipdb_api_key"
  end

  local output = {"Threat Intelligence для IP: " .. ip}

  if vt_key then
    local data, err = virus_total_lookup(vt_key, ip)
    if data then
      local stats = data.data and data.data.attributes and data.data.attributes.last_analysis_stats
      if stats then
        table.insert(output, "VirusTotal: вредоносных=" .. (stats.malicious or 0) .. ", подозрительных=" .. (stats.suspicious or 0))
      else
        table.insert(output, "VirusTotal: данных нет")
      end
    else
      table.insert(output, "VirusTotal ошибка: " .. err)
    end
  end

  if otx_key then
    local data, err = alienvault_otx_lookup(otx_key, ip)
    if data then
      local pulse_count = data.pulse_info and data.pulse_info.count or 0
      table.insert(output, "AlienVault OTX: число пульсов=" .. pulse_count)
    else
      table.insert(output, "AlienVault OTX ошибка: " .. err)
    end
  end

  if abuse_key then
    local data, err = abuseipdb_lookup(abuse_key, ip)
    if data and data.data then
      local abuse_confidence = data.data.abuseConfidenceScore or 0
      local total_reports = data.data.totalReports or 0
      table.insert(output, "AbuseIPDB: рейтинг угрозы=" .. abuse_confidence .. ", отчетов=" .. total_reports)
    else
      table.insert(output, "AbuseIPDB ошибка: " .. err)
    end
  end

  return table.concat(output, "\n")
end
