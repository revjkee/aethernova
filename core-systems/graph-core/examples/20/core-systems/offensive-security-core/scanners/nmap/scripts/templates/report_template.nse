-- templates/report_template.nse
--
-- Шаблон для создания отчетов по результатам сканирования Nmap
-- Включает базовую структуру вывода, форматирование и основные данные
--
-- Используется как основа для кастомизации и генерации итоговых отчетов

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
  Шаблонный скрипт для генерации отчетов по результатам сканирования.
  Позволяет выводить структурированные данные по хостам и портам.
]]

author = "TeslaAI Genesis Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"report", "safe"}

-- Основная функция запуска скрипта
action = function(host)

  local output = {}
  table.insert(output, string.format("Отчет по хосту: %s", host.ip))
  table.insert(output, string.rep("-", 50))

  -- Информация о состоянии хоста
  if host.status and host.status.state then
    table.insert(output, string.format("Статус: %s", host.status.state))
  end

  -- Информация о сервисах и открытых портах
  if host.ports then
    for _, port in ipairs(host.ports) do
      if port.state == "open" then
        local service = port.service or {}
        table.insert(output, string.format(
          "Порт %d/%s - %s %s",
          port.number, port.protocol,
          service.name or "неизвестно",
          service.product or ""
        ))
      end
    end
  end

  -- Пример добавления пользовательских данных (если есть)
  if host.script_results then
    table.insert(output, "Результаты скриптов:")
    for name, result in pairs(host.script_results) do
      table.insert(output, string.format(" - %s: %s", name, tostring(result)))
    end
  end

  return stdnse.format_output(true, output)
end
