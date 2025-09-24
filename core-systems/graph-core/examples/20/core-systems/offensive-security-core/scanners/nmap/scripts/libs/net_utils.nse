-- net_utils.nse
--
-- Универсальный набор сетевых утилит для Nmap NSE скриптов.
-- Содержит функции для работы с IP, TCP/UDP сокетами, преобразованиями и проверками.

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local bit = require "bit"
local math = require "math"

_ENV = stdnse.module("net_utils", stdnse.seeall)

-- Проверка валидности IPv4 адреса
function is_valid_ipv4(ip)
  if not ip then return false end
  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks ~= 4 then return false end
  for _, v in ipairs(chunks) do
    local n = tonumber(v)
    if not n or n < 0 or n > 255 then return false end
  end
  return true
end

-- Проверка валидности IPv6 адреса (простейшая, по шаблону)
function is_valid_ipv6(ip)
  if not ip then return false end
  local parts = {ip:match("^(%x*:%x*:%x*:%x*:%x*:%x*:%x*:%x*)$")}
  return #parts > 0
end

-- Преобразование IPv4 из строки в 32-битное число
function ipv4_to_number(ip)
  local a,b,c,d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  return bit.lshift(tonumber(a),24) + bit.lshift(tonumber(b),16) + bit.lshift(tonumber(c),8) + tonumber(d)
end

-- Преобразование 32-битного числа в IPv4 строку
function number_to_ipv4(num)
  local a = bit.rshift(num,24) % 256
  local b = bit.rshift(num,16) % 256
  local c = bit.rshift(num,8) % 256
  local d = num % 256
  return string.format("%d.%d.%d.%d", a,b,c,d)
end

-- Генерация случайного порта (1024-65535)
function random_port()
  return math.random(1024, 65535)
end

-- Создание TCP-сокета и подключение (возвращает объект сокета или nil+error)
function tcp_connect(host, port, timeout)
  timeout = timeout or 5000
  local sock = nmap.new_socket()
  sock:set_timeout(timeout)
  local status, err = sock:connect(host, port)
  if not status then
    sock:close()
    return nil, err
  end
  return sock
end

-- Закрытие сокета с безопасным try/catch
function safe_close(sock)
  if sock then
    local status, err = pcall(sock.close, sock)
    if not status then
      stdnse.print_debug(1, "Ошибка при закрытии сокета: %s", err)
    end
  end
end

-- Разбор сетевого диапазона (CIDR) на список IP
function cidr_to_ips(cidr)
  local ip, mask = cidr:match("([^/]+)/(%d+)")
  if not ip or not mask then return nil end
  mask = tonumber(mask)
  if not is_valid_ipv4(ip) or mask < 0 or mask > 32 then return nil end

  local start_num = ipv4_to_number(ip) & (bit.lshift(0xFFFFFFFF, 32 - mask))
  local count = bit.lshift(1, 32 - mask)

  local ips = {}
  for i = 0, count - 1 do
    table.insert(ips, number_to_ipv4(start_num + i))
  end
  return ips
end

-- Проверка открытости TCP-порта (возвращает true/false)
function is_tcp_port_open(host, port, timeout)
  local sock, err = tcp_connect(host, port, timeout)
  if sock then
    safe_close(sock)
    return true
  else
    return false, err
  end
end

return _ENV
