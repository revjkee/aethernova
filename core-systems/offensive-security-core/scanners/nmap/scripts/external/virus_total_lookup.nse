-- virus_total_lookup.nse
--
-- Скрипт для запроса информации из VirusTotal по IP или хосту
-- Требуется API ключ VirusTotal
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
Получает информацию из VirusTotal API по IP или хосту.
]]

author = "TeslaAI Expert"

license = "Same as Nmap -- https://nmap.org/book/man-legal.html"

categories = {"external", "discovery", "safe"}

portrule = function(host)
  return host.ip ~= nil
end

local function virus_total_query(api_key, query)
  local base_url = "https://www.virustotal.com/api/v3/ip_addresses/" .. url.escape(query)
  local response_body = {}

  local res, code, headers, status = https.request{
    url = base_url,
    headers = {
      ["x-apikey"] = api_key,
      ["User-Agent"] = "Nmap VT NSE Script"
    },
    sink = ltn12.sink.table(response_body),
    protocol = "tlsv1_2"
  }

  if code ~= 200 then
    return nil, "VirusTotal API error: HTTP code " .. tostring(code)
  end

  local body = table.concat(response_body)
  local data = json.decode(body)
  if not data then
    return nil, "Ошибка декодирования JSON ответа"
  end

  return data, nil
end

action = function(host)
  local api_key = stdnse.get_script_args("virus_total_api_key")
  if not api_key then
    return "Требуется аргумент 'virus_total_api_key' с вашим API ключом VirusTotal"
  end

  local query = host.ip
  local data, err = virus_total_query(api_key, query)
  if not data then
    return "Ошибка запроса к VirusTotal: " .. err
  end

  local output = {}
  table.insert(output, "VirusTotal информация для " .. query .. ":")

  if data.data and data.data.attributes then
    local attr = data.data.attributes
    if attr.country then
      table.insert(output, "Страна: " .. attr.country)
    end
    if attr.asn then
      table.insert(output, "ASN: " .. attr.asn)
    end
    if attr.last_analysis_stats then
      local stats = attr.last_analysis_stats
      table.insert(output, "Анализ: вредоносных=" .. (stats.malicious or 0) .. ", подозрительных=" .. (stats.suspicious or 0))
    end
    if attr.last_modification_date then
      table.insert(output, "Последнее обновление: " .. os.date("%Y-%m-%d %H:%M:%S", attr.last_modification_date))
    end
  else
    table.insert(output, "Нет детальной информации")
  end

  return table.concat(output, "\n")
end
