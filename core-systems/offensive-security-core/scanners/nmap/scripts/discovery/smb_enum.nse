-- smb_enum.nse
--
-- Скрипт для сбора информации о SMB сервисах, доступных ресурсах и правах
--
-- Требования:
--   nmap 7.80+
--   smb библиотека Nmap
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Выполняет SMB enumeration для получения списка доступных ресурсов, информации о сессиях и правах пользователя.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = nmap.portsWithService("microsoft-ds", "netbios-ssn")

action = function(host, port)
  local status, smbstate = smb.get_smb_state(host, port)
  if not status then
    return "SMB сервис недоступен."
  end

  local output = {}
  table.insert(output, "SMB Enumeration на " .. host.ip)

  -- Получить список доступных ресурсов
  local shares = smb.list_shares(smbstate)
  if shares and #shares > 0 then
    table.insert(output, "Доступные SMB ресурсы:")
    for _, share in ipairs(shares) do
      table.insert(output, " - " .. share.name .. " (" .. share.type .. ")")
    end
  else
    table.insert(output, "Ресурсы не обнаружены.")
  end

  -- Попытка получить информацию о сессиях
  local sessions = smb.enum_sessions(smbstate)
  if sessions and #sessions > 0 then
    table.insert(output, "Активные SMB сессии:")
    for _, session in ipairs(sessions) do
      table.insert(output, " - Пользователь: " .. session.username .. ", Хост: " .. session.client_name)
    end
  else
    table.insert(output, "Активные сессии не найдены.")
  end

  return stdnse.format_output(true, table.concat(output, "\n"))
end
