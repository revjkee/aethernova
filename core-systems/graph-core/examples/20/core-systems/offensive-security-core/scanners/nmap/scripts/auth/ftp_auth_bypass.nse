-- ftp_auth_bypass.nse
--
-- Скрипт для выявления и эксплуатации обхода аутентификации на FTP серверах
-- Использует набор техник для проверки возможности анонимного доступа
-- или обхода аутентификации с нестандартными параметрами.

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ftp = require "ftp"

description = [[
Проверка FTP-сервера на возможность обхода аутентификации.
Пытается анонимный вход и вход с пустым паролем,
а также некоторые распространённые обходы.
]]

author = "TeslaAI Expert"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

portrule = shortport.port_or_service({21}, {"ftp"})

-- Основная функция сканирования
action = function(host, port)
  local status, result
  local output = {}

  -- Создаем FTP сессию
  local conn = ftp.new(host, port)
  if not conn then
    return "Не удалось установить соединение с FTP"
  end

  -- Пробуем анонимный вход
  status, result = conn:login("anonymous", "anonymous@domain.com")
  if status then
    table.insert(output, "Успешный анонимный вход")
  else
    -- Пробуем пустой пароль с пользователем 'ftp'
    status, result = conn:login("ftp", "")
    if status then
      table.insert(output, "Обход аутентификации: вход ftp с пустым паролем")
    else
      -- Дополнительные проверки обхода (например, спецсимволы)
      local bypass_attempts = {
        {"root", " "},
        {"admin", "admin"},
        {"test", ""},
        {"anonymous", ""},
      }

      for _, creds in ipairs(bypass_attempts) do
        status, result = conn:login(creds[1], creds[2])
        if status then
          table.insert(output, "Обход аутентификации: вход с " .. creds[1] .. "/" .. creds[2])
          break
        end
      end
    end
  end

  conn:disconnect()

  if #output == 0 then
    return "Обход аутентификации не обнаружен"
  else
    return table.concat(output, "; ")
  end
end
