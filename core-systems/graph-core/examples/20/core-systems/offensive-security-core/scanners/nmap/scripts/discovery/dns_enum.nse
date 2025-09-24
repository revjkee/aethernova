-- dns_enum.nse
--
-- Скрипт для комплексной DNS-энумерации домена.
--
-- Требования:
--   nmap 7.80+
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local dns = require "dns"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
Выполняет расширенную DNS-энумерацию: рекурсивные запросы, проверка зонального трансфера, получение A, AAAA, MX, NS, TXT записей.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, {"domain"})

local function attempt_zone_transfer(target)
  local zones = {}
  local ns_servers = {}

  local status, result = dns.query(target, "NS")
  if not status then
    return nil, "Ошибка получения NS записей: " .. tostring(result)
  end

  for _, ns in ipairs(result) do
    table.insert(ns_servers, ns.string)
  end

  local transfers = {}
  for _, ns in ipairs(ns_servers) do
    local transfer_result = dns.zone_transfer(ns, target)
    if transfer_result then
      table.insert(transfers, {ns=ns, data=transfer_result})
    end
  end

  if #transfers > 0 then
    return transfers
  else
    return nil, "Зональный трансфер не удался или запрещен"
  end
end

action = function(host, port)
  local results = {}

  local target = host.targetname or host.name or host.ip
  if not target then
    return "DNS имя не найдено для цели"
  end

  stdnse.print_debug(1, "Запуск dns_enum для %s", target)

  -- Запрос A записи
  local a_status, a_records = dns.query(target, "A")
  if a_status and a_records then
    table.insert(results, "A записи:")
    for _, rec in ipairs(a_records) do
      table.insert(results, "  " .. rec.string)
    end
  end

  -- Запрос AAAA записи
  local aaaa_status, aaaa_records = dns.query(target, "AAAA")
  if aaaa_status and aaaa_records then
    table.insert(results, "AAAA записи:")
    for _, rec in ipairs(aaaa_records) do
      table.insert(results, "  " .. rec.string)
    end
  end

  -- Запрос MX записи
  local mx_status, mx_records = dns.query(target, "MX")
  if mx_status and mx_records then
    table.insert(results, "MX записи:")
    for _, rec in ipairs(mx_records) do
      table.insert(results, string.format("  %s (приоритет %d)", rec.exchange, rec.preference))
    end
  end

  -- Запрос NS записи
  local ns_status, ns_records = dns.query(target, "NS")
  if ns_status and ns_records then
    table.insert(results, "NS записи:")
    for _, rec in ipairs(ns_records) do
      table.insert(results, "  " .. rec.string)
    end
  end

  -- Запрос TXT записи
  local txt_status, txt_records = dns.query(target, "TXT")
  if txt_status and txt_records then
    table.insert(results, "TXT записи:")
    for _, rec in ipairs(txt_records) do
      table.insert(results, "  " .. table.concat(rec.strings, " "))
    end
  end

  -- Попытка зонального трансфера
  local zone_transfer_result, err = attempt_zone_transfer(target)
  if zone_transfer_result then
    table.insert(results, "Успешный зональный трансфер:")
    for _, transfer in ipairs(zone_transfer_result) do
      table.insert(results, "От NS: " .. transfer.ns)
      for _, entry in ipairs(transfer.data) do
        table.insert(results, "  " .. entry)
      end
    end
  else
    table.insert(results, "Зональный трансфер: " .. tostring(err))
  end

  return table.concat(results, "\n")
end
