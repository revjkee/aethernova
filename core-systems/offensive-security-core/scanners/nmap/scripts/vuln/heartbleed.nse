-- heartbleed.nse
--
-- Проверяет уязвимость CVE-2014-0160 (Heartbleed) в OpenSSL, позволяющую удалённому атакующему читать произвольную память сервера.
--
-- Автор: TeslaAI Red Team, на основе оригинального PoC
-- Лицензия: Same as Nmap

local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local vulns = require "vulns"
local openssl_heartbleed = require "openssl_heartbleed"

description = [[
Обнаруживает CVE-2014-0160 (Heartbleed) — критическую уязвимость в OpenSSL,
позволяющую злоумышленнику извлекать данные из памяти процесса, включая ключи, токены, логины.
]]

author = "TeslaAI Red Team (на основе оригинала от Jared Stafford)"

license = "Same as Nmap"

categories = {"vuln", "exploit", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local vuln_report = vulns.Report:new({
    title = "Heartbleed (CVE-2014-0160) memory disclosure vulnerability",
    state = vulns.STATE.NOT_VULN,
    description = description,
    risk_factor = "Critical",
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160",
      "https://www.openssl.org/news/secadv/20140407.txt"
    }
  })

  local status, result = openssl_heartbleed.check(host, port)

  if not status then
    return stdnse.format_output(false, "Ошибка проверки: %s", result or "неизвестная")
  end

  if result.vulnerable then
    vuln_report.state = vulns.STATE.VULN
    vuln_report.extra_info = string.format("Получено %d байт утёкших данных. Сервер уязвим.", #result.data)
  else
    vuln_report.state = vulns.STATE.NOT_VULN
  end

  return vuln_report:make_output()
end
