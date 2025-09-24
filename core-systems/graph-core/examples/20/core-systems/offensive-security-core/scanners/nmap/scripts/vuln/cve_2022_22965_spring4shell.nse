-- cve_2022_22965_spring4shell.nse
--
-- Обнаруживает наличие уязвимости Spring4Shell (CVE-2022-22965) в приложениях на базе Spring Core.
--
-- Поддерживает отправку crafted POST-запроса на подозрительный endpoint для проверки наличия уязвимости.
--
-- Автор: TeslaAI Red Team
-- Лицензия: Same as Nmap

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"
local vulns = require "vulns"

description = [[
Проверяет наличие CVE-2022-22965 (Spring4Shell) — критической RCE уязвимости
в Spring Core, позволяющей злоумышленнику выполнять команды через передачу
вредоносных параметров в POST-запросах.

Работает на приложениях, использующих Tomcat с уязвимыми версиями Spring (до 5.3.18 / 5.2.20).
]]

author = "TeslaAI Red Team"

license = "Same as Nmap"

categories = {"vuln", "exploit", "rce"}

portrule = shortport.http

action = function(host, port)
  local vuln_report = vulns.Report:new({
    title = "Spring4Shell Remote Code Execution (CVE-2022-22965)",
    state = vulns.STATE.NOT_VULN,
    description = description,
    risk_factor = "Critical",
    references = {
      "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
      "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
    }
  })

  local paths = {
    "/actuator/env", "/error", "/actuator", "/index", "/"
  }

  for _, path in ipairs(paths) do
    local url = http.url.build(host, port, path)
    local payload = "class.module.classLoader.URLs[0]=0&class.module.classLoader.DefaultAssertionStatus=true"

    local response = http.post(host, port, path, payload, {
      header = {
        ["Content-Type"] = "application/x-www-form-urlencoded"
      }
    })

    if response and response.status and response.status >= 200 and response.status < 300 then
      if response.body and (response.body:find("org.springframework") or response.body:find("Whitelabel Error Page")) then
        vuln_report.state = vulns.STATE.LIKELY_VULN
        vuln_report.extra_info = string.format("Путь %s ответил статусом %s. Присутствуют признаки Spring-приложения.", path, response.status)
        break
      end
    end
  end

  return vuln_report:make_output()
end
