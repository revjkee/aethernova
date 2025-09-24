-- smb_auth_check.nse
--
-- Проверяет возможность аутентификации на SMB-сервере с помощью перебора учетных данных.
-- Использует стандартные и пользовательские списки логинов и паролей.
-- Помогает выявить слабые SMB-учетные записи.
--
-- Требования:
--   nmap 7.80+, NSE smb библиотека, LuaSocket
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
local table = require "table"

description = [[
Проверка SMB аутентификации с перебором паролей.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(445, "microsoft-ds")

local default_users = {"Administrator", "Guest", "User", "Admin", "test"}
local default_passwords = {"", "password", "123456", "admin", "guest"}

local function try_smb_auth(host, user, pass)
  local status, err = smb.auth(host, user, pass)
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
      local success, err = try_smb_auth(host.ip, user, pass)
      if success then
        table.insert(results, string.format("Успешный вход SMB: %s:%s", user, pass))
      end
    end
  end

  if #results == 0 then
    return "Не найдено успешных учетных данных SMB"
  else
    return table.concat(results, "; ")
  end
end
