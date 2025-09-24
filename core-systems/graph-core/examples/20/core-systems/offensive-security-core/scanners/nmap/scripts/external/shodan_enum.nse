-- shodan_enum.nse
--
-- Скрипт для получения информации из Shodan API по целевому хосту.
--
-- Требования:
--   - Nmap 7.80+
--   - LuaSocket, JSON библиотеки
--   - Настроенный Shodan API ключ (через аргументы)
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"
local https = require "ssl.https"
local url = require "socket.url"

description = [[
Использует Shodan API для сбора расширенной информации о целевом хосте по IP.
]]

author = "TeslaAI Expert"

license = "Same as Nmap -- https://nmap.org/book/man-legal.html"

categories = {"external", "discovery", "safe"}

portrule = function(host)
  return host.ip ~= nil
end

local function shodan_query(api_key, ip)
  local query_url = "https://api.shodan.io/shodan/host/" .. ip .. "?key=" .. api_key
  local response_body = {}

  local res, code, headers, status = https.request{
    url = query_url,
    sink = ltn12.sink.table(response_body),
    protocol = "tlsv1_2"
  }

  if code ~= 200 then
    return nil, "Ошибка Shodan API: HTTP код " .. tostring(code)
  end

  local body = table.concat(response_body)
  local data = json.decode(body)

  if not data then
    return nil, "Ошибка декодирования JSON ответа"
  end

  return data, nil
end

action = function(host)
  local api_key = stdnse.get_script_args("shodan_api_key")
  if not api_key then
    return "Требуется аргумент 'shodan_api_key' с вашим API ключом Shodan"
  end

  local data, err = shodan_query(api_key, host.ip)
  if not data then
    return "Ошибка запроса к Shodan: " .. err
  end

  local output = {}
  table.insert(output, "Shodan информация для " .. host.ip .. ":")
  if data.org then
    table.insert(output, "Организация: " .. data.org)
  end
  if data.os then
    table.insert(output, "ОС: " .. data.os)
  end
  if data.ports then
    table.insert(output, "Открытые порты: " .. table.concat(data.ports, ", "))
  end
  if data.vulns then
    table.insert(output, "Уязвимости: " .. table.concat(data.vulns, ", "))
  end

  return table.concat(output, "\n")
end
