-- host_discovery.nse
--
-- Скрипт для многоуровневого обнаружения активных хостов в сети.
--
-- Требования:
--   nmap 7.80+
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local stdnse = require "stdnse"
local ipOps = require "ipOps"
local packet = require "packet"
local coroutine = require "coroutine"
local bin = require "bin"
local socket = require "socket"
local shortport = require "shortport"

description = [[
Выполняет обнаружение хостов с помощью ICMP Echo, TCP SYN на распространённые порты, а также ARP-пинги (для локальной сети).
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(80, "tcp") -- запускается на любом активном порту

local function send_icmp_echo(host)
  local icmp = packet.ICMP:new()
  icmp:type(8) -- Echo request
  icmp:code(0)
  icmp:checksum(0)
  icmp:data("nmap host discovery")
  icmp:checksum(icmp:build_checksum())

  local ip = packet.IP:new()
  ip:version(4)
  ip:ttl(64)
  ip:protocol(packet.IPPROTO_ICMP)
  ip:src("0.0.0.0") -- будет подставлен автоматически
  ip:dst(host.ip)
  ip:data(icmp:build())

  local rawsock = nmap.new_dnet()
  rawsock:ip_open()

  rawsock:ip_send(ip:build())
  rawsock:ip_close()
end

local function send_tcp_syn(host, port)
  local eth = packet.Ethernet:new()
  local ip = packet.IP:new()
  local tcp = packet.TCP:new()

  tcp:flags("S")
  tcp:sport(math.random(1024, 65535))
  tcp:dport(port)
  tcp:seq(0)
  tcp:win(14600)

  ip:version(4)
  ip:ttl(64)
  ip:protocol(packet.IPPROTO_TCP)
  ip:src("0.0.0.0") -- будет подставлен автоматически
  ip:dst(host.ip)
  ip:data(tcp:build())

  eth:data(ip:build())

  local rawsock = nmap.new_dnet()
  rawsock:eth_open()
  rawsock:eth_send(eth:build())
  rawsock:eth_close()
end

action = function(host)
  local results = {}

  stdnse.print_debug(1, "Начало host_discovery для %s", host.ip)

  -- ARP ping (для локальных сетей)
  if ipOps.isInLocalNetwork(host.ip) then
    local status, err = nmap.arp_ping(host.ip)
    if status then
      table.insert(results, "Host отвечает на ARP ping")
      return table.concat(results, "\n")
    end
  end

  -- ICMP Echo ping
  local icmp_status = nmap.icmp_ping(host.ip)
  if icmp_status then
    table.insert(results, "Host отвечает на ICMP Echo ping")
    return table.concat(results, "\n")
  end

  -- TCP SYN ping по распространённым портам (80, 443, 22)
  local ports = {80, 443, 22}
  for _, port in ipairs(ports) do
    local syn_status = nmap.tcp_syn_ping(host.ip, port)
    if syn_status then
      table.insert(results, "Host отвечает на TCP SYN ping на порту " .. port)
      return table.concat(results, "\n")
    end
  end

  table.insert(results, "Host не обнаружен с помощью доступных методов")
  return table.concat(results, "\n")
end
