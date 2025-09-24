-- kerberos_ticket_enum.nse
--
-- Скрипт для перечисления и проверки Kerberos тикетов на целевом хосте.
-- Помогает выявить уязвимости, связанные с Kerberos аутентификацией.
--
-- Требования:
--   nmap 7.80+, NSE kerberos библиотека, LuaSocket
--
-- Автор: TeslaAI Expert
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local kerberos = require "kerberos"
local string = require "string"
local table = require "table"

description = [[
Перечисляет Kerberos тикеты, проверяет их валидность и возможность использования.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(88, "kerberos")

local function enumerate_kerberos_tickets(host)
  local tickets = {}
  local success, err = kerberos.connect(host.ip, 88)
  if not success then
    return nil, "Ошибка подключения к Kerberos: " .. (err or "неизвестная ошибка")
  end

  local list, err = kerberos.list_tickets()
  if not list then
    return nil, "Ошибка получения тикетов: " .. (err or "неизвестная ошибка")
  end

  for _, ticket in ipairs(list) do
    local valid, err = kerberos.validate_ticket(ticket)
    if valid then
      table.insert(tickets, string.format("Валидный тикет: %s", ticket.service))
    end
  end

  return tickets
end

action = function(host, port)
  local tickets, err = enumerate_kerberos_tickets(host)
  if not tickets then
    return "Ошибка Kerberos тикетов: " .. (err or "неизвестная ошибка")
  end

  if #tickets == 0 then
    return "Валидных Kerberos тикетов не обнаружено"
  end

  return table.concat(tickets, "; ")
end
