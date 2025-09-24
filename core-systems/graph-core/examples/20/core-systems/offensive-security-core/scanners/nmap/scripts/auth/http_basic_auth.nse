-- http_basic_auth.nse
--
-- Скрипт для обнаружения и тестирования HTTP Basic Authentication.
-- Проверяет наличие аутентификации на HTTP(S) ресурсах и
-- осуществляет подбор по словарю базовых учетных данных.

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local base64 = require "base64"
local string = require "string"

description = [[
Проверка HTTP Basic Authentication и подбор учетных данных.
Сканирует веб-сервер на наличие Basic Auth и пробует стандартные пары логин/пароль.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive", "safe"}

portrule = shortport.http

local default_users = {
  "admin", "user", "test", "guest", "root"
}

local default_passwords = {
  "admin", "password", "123456", "test", ""
}

local function build_auth_header(user, pass)
  local token = base64.encode(user .. ":" .. pass)
  return "Basic " .. token
end

action = function(host, port)
  local path = "/"
  local url = string.format("http%s://%s:%d%s",
    port.service == "https" and "s" or "", host.targetname or host.ip, port.number, path)

  local results = {}

  -- Первая проверка: есть ли Basic Auth вообще
  local response = http.get(host, port, path)
  if not response or not response.header then
    return "Не удалось получить ответ от сервера"
  end

  local www_auth = response.header["www-authenticate"]
  if not www_auth or not www_auth:lower():find("basic") then
    return "HTTP Basic Auth не обнаружен"
  end

  -- Пытаемся перебрать учетные данные из дефолтных списков
  for _, user in ipairs(default_users) do
    for _, pass in ipairs(default_passwords) do
      local headers = {
        ["Authorization"] = build_auth_header(user, pass)
      }

      local resp = http.get(host, port, path, {header = headers})

      if resp and resp.status == 200 then
        table.insert(results, string.format("Успешный вход с %s:%s", user, pass))
        -- Можно прервать на первом успехе, если нужно:
        -- return table.concat(results, "; ")
      end
    end
  end

  if #results == 0 then
    return "Подбор учетных данных HTTP Basic Auth не дал результатов"
  else
    return table.concat(results, "; ")
  end
end
