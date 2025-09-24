-- ssl_cert_info.nse
--
-- Скрипт для получения информации о SSL-сертификатах сервера
--
-- Требования:
--   nmap 7.80+
--   ssl библиотека Nmap
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local ssl = require "ssl"
local stdnse = require "stdnse"
local shortport = require "shortport"
local openssl_x509 = require "openssl.x509"
local string = require "string"

description = [[
Получение и парсинг SSL-сертификатов, анализ срока действия, цепочки доверия и основных параметров.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.ssl

local function get_cert_info(host, port)
  local status, sock = nmap.new_socket()
  if not status then
    return nil, "Не удалось создать сокет: " .. sock
  end

  sock:set_timeout(5000)
  local status, err = sock:connect(host, port)
  if not status then
    return nil, "Не удалось подключиться: " .. err
  end

  local params = {
    mode = "client",
    protocol = "tlsv1_2",
    verify = "none",
    options = {"all", "no_sslv2", "no_sslv3"}
  }

  local sslsock = ssl.wrap(sock, params)
  status, err = sslsock:dohandshake()
  if not status then
    sock:close()
    return nil, "Ошибка SSL рукопожатия: " .. err
  end

  local cert = sslsock:getpeercertificate()
  sock:close()

  if not cert then
    return nil, "Сертификат не получен"
  end

  return cert
end

action = function(host, port)
  local cert, err = get_cert_info(host.ip, port.number)
  if not cert then
    return "Ошибка получения сертификата: " .. err
  end

  local output = {}

  local subject = cert:get_subject()
  local issuer = cert:get_issuer()
  local notbefore = cert:get_notbefore()
  local notafter = cert:get_notafter()

  table.insert(output, "SSL сертификат для " .. host.ip .. ":" .. port.number)
  table.insert(output, "Subject: " .. tostring(subject))
  table.insert(output, "Issuer: " .. tostring(issuer))
  table.insert(output, "Действителен с: " .. tostring(notbefore))
  table.insert(output, "Действителен до: " .. tostring(notafter))

  return stdnse.format_output(true, table.concat(output, "\n"))
end
