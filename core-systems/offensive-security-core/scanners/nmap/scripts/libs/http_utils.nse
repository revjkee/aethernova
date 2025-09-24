-- http_utils.nse
--
-- Набор расширенных утилит для работы с HTTP в Nmap NSE-скриптах.
-- Используется для создания, отправки, декодирования и обработки HTTP-запросов и ответов.

local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
local json = require "json"

_ENV = stdnse.module("http_utils", stdnse.seeall)

-- Отправка GET-запроса
function http_get(host, port, path, headers)
  local options = {
    header = headers or {},
    timeout = 10000,
    port = port or 80
  }
  return http.get(host, path or "/", options)
end

-- Отправка POST-запроса с телом
function http_post(host, port, path, body, headers)
  local options = {
    header = headers or { ["Content-Type"] = "application/x-www-form-urlencoded" },
    timeout = 10000,
    port = port or 80
  }
  return http.post(host, path or "/", body or "", options)
end

-- Отправка произвольного HTTP-запроса (полный контроль)
function raw_http_request(host, port, req_raw)
  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  local status, err = socket:connect(host, port)
  if not status then return nil, err end
  socket:send(req_raw)
  local response = socket:receive_lines(1)
  socket:close()
  return response
end

-- Извлечение заголовков из HTTP-ответа
function parse_headers(raw_data)
  local headers = {}
  for line in string.gmatch(raw_data, "[^\r\n]+") do
    local key, val = line:match("^([^:]+):%s*(.+)$")
    if key and val then
      headers[string.lower(key)] = val
    end
  end
  return headers
end

-- Проверка наличия заданного заголовка
function has_header(response, header_name)
  local headers = parse_headers(response)
  return headers[string.lower(header_name)] ~= nil
end

-- Декодирование JSON-тела
function parse_json_body(body)
  local status, decoded = pcall(json.decode, body)
  if status then
    return decoded
  end
  return nil
end

-- Преобразование таблицы в строку запроса
function table_to_query(tbl)
  local out = {}
  for k, v in pairs(tbl) do
    table.insert(out, url.escape(k) .. "=" .. url.escape(v))
  end
  return table.concat(out, "&")
end

-- Простой HTTP-ping
function http_ping(host, port)
  local status, res = http_get(host, port, "/")
  return status and res.status == 200
end

-- Выделение тела ответа
function extract_body(response)
  local body = response:match("\r\n\r\n(.*)")
  return body or ""
end

return _ENV
