-- netbios_enum.nse
--
-- Скрипт для сбора информации о NetBIOS-ресурсах на целевых хостах
--
-- Требования:
--   nmap 7.80+
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local stdnse = require "stdnse"
local socket = require "socket"
local bin = require "bin"
local comm = require "comm"

description = [[
Выполняет NetBIOS enumeration для выявления имён, сервисов и доступных ресурсов на целевых системах.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = nmap.portsWithService("netbios-ssn")

local function parse_netbios_response(data)
  local names = {}
  for name in data:gmatch("([%w%p]+)%z") do
    table.insert(names, name)
  end
  return names
end

action = function(host, port)
  local status, result = nmap.fetch_port_state(host, port)
  if not status or result ~= "open" then
    return
  end

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local success, err = socket:connect(host.ip, port.number)
  if not success then
    return "Не удалось подключиться к NetBIOS сервису: " .. err
  end

  local query_packet = "\x81\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
  socket:send(query_packet)

  local status, response = socket:receive_bytes(1024)
  socket:close()

  if not status then
    return "Нет ответа на NetBIOS запрос."
  end

  local names = parse_netbios_response(response)
  if #names == 0 then
    return "NetBIOS имена не найдены."
  end

  return stdnse.format_output(true,
    "NetBIOS имена и ресурсы:",
    table.concat(names, ", ")
  )
end
