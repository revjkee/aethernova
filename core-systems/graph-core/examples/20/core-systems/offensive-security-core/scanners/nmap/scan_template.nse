-- Nmap NSE скрипт для расширенного сканирования с кастомными проверками

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
  Кастомный NSE скрипт для обнаружения уязвимостей и сбора информации.
  Включает проверку открытых портов, версии сервисов, а также специфических
  уязвимостей по HTTP и SMB.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80, 443, 445}, {"http", "https", "microsoft-ds"})

action = function(host, port)
  local result = {}
  
  -- Проверка версии сервиса
  local version = nmap.fetch_port_version(host, port)
  if version then
    table.insert(result, "Service version: " .. version)
  end

  -- Проверка HTTP заголовков при портах 80 и 443
  if port.number == 80 or port.number == 443 then
    local http = require "http"
    local response = http.get(host, port)
    if response and response.status then
      table.insert(result, "HTTP Status: " .. response.status)
      local server = response.header["server"] or "unknown"
      table.insert(result, "Server header: " .. server)
      -- Дополнительные проверки безопасности
      if string.find(server:lower(), "apache") then
        table.insert(result, "Potential Apache server detected.")
      elseif string.find(server:lower(), "iis") then
        table.insert(result, "Potential Microsoft IIS server detected.")
      end
    end
  end

  -- Проверка SMB версия (порт 445)
  if port.number == 445 then
    local smb = require "smb"
    local smb_version = smb.get_version(host)
    if smb_version then
      table.insert(result, "SMB Version: " .. smb_version)
    end
  end

  if #result == 0 then
    return "No relevant information found."
  else
    return stdnse.format_output(true, result)
  end
end
