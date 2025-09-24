-- version_detection.nse
--
-- Скрипт для обнаружения версии сервисов на целевом хосте
--
-- Требования:
--   nmap 7.80+
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local comm = require "comm"

description = [[
Скрипт пытается определить версии сервисов, запущенных на открытых портах.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "version"}

portrule = shortport.port_or_service({21,22,23,25,80,443,3306,3389,5900,8080}, "tcp")

local function grab_banner(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local status, err = socket:connect(host, port)
  if not status then
    return nil, "Не удалось подключиться: " .. err
  end

  -- Попытка получить баннер, послав пустой запрос или команду
  local ok, err = socket:send("\n")
  if not ok then
    socket:close()
    return nil, "Ошибка отправки запроса: " .. err
  end

  local status, data = socket:receive_lines(1)
  socket:close()
  if not status then
    return nil, "Ошибка чтения баннера: " .. data
  end

  return data
end

action = function(host, port)
  local banner, err = grab_banner(host.ip, port.number)
  if not banner then
    return "Ошибка получения баннера: " .. err
  end

  -- Простая попытка извлечь версию из баннера
  local version = banner:match("version%s*:?%s*([%w%.%-_]+)") or banner:match("(%d+%.%d+%.?%d*)") or banner

  return stdnse.format_output(true, "Порт: " .. port.number .. "\nВерсия сервиса: " .. version)
end
