-- http_bruteforce.nse
--
-- Скрипт для перебора учётных данных HTTP (Basic Auth и формы)
-- Поддерживает проверку базовой аутентификации и простых форм входа.
--
-- Требования:
--   nmap 7.80+, NSE http библиотека, LuaSocket
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"
local creds = require "creds" -- внешний словарь логинов/паролей

description = [[
Перебор HTTP Basic Auth и простых форм авторизации для выявления слабых паролей.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"brute", "intrusive"}

portrule = shortport.http

local function try_basic_auth(host, port, user, pass)
  local headers = {
    ["Authorization"] = "Basic " .. stdnse.to_base64(user .. ":" .. pass)
  }
  local response = http.get(host, port, "/", {header = headers})
  if response and response.status == 200 then
    return true
  end
  return false
end

local function try_form_auth(host, port, user, pass)
  local url = "/login"  -- Можно сделать настраиваемым
  local body = string.format("username=%s&password=%s", user, pass)
  local response = http.post(host, port, url, body, {header = {["Content-Type"] = "application/x-www-form-urlencoded"}})
  if response and response.status == 200 and not string.match(response.body or "", "invalid") then
    return true
  end
  return false
end

action = function(host, port)
  local results = {}

  for _, cred in ipairs(creds) do
    local user = cred.username
    local pass = cred.password

    if try_basic_auth(host, port, user, pass) then
      table.insert(results, string.format("Успешный Basic Auth: %s / %s", user, pass))
      break
    end

    if try_form_auth(host, port, user, pass) then
      table.insert(results, string.format("Успешный Form Auth: %s / %s", user, pass))
      break
    end
  end

  if #results == 0 then
    return "Перебор неудачен. Уязвимых учётных записей не обнаружено."
  end

  return table.concat(results, "\n")
end
