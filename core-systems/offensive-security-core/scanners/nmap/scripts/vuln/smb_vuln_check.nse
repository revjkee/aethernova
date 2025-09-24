-- smb_vuln_check.nse
--
-- Глубокий аудит известных уязвимостей SMB-серверов (MS17-010, CVE-2020-0796, CVE-2017-0143 и др.)
-- Используется для быстрой оценки степени риска при пентесте или Red Team операции.
--
-- Автор: TeslaAI Red Team
-- Лицензия: Same as Nmap

local shortport = require "shortport"
local smb = require "smb"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Проверяет SMB-сервер на наличие критических уязвимостей, включая:

- MS17-010 (EternalBlue)
- CVE-2020-0796 (SMBGhost)
- CVE-2017-0143 (SMB RCE)
- SMB Signing Status
- Guest Access/Null Session
]]

author = "TeslaAI Red Team"

license = "Same as Nmap"

categories = {"vuln", "safe", "intrusive"}

portrule = shortport.port_or_service(445, "microsoft-ds")

action = function(host, port)
  local vuln_report = vulns.Report:new({
    title = "SMB Vulnerability Audit",
    state = vulns.STATE.NOT_VULN,
    description = description,
    risk_factor = "Critical",
    references = {
      "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796"
    }
  })

  local status, smbstate = smb.start_session(host, port)
  if not status then
    return stdnse.format_output(false, "SMB сессия не установлена: %s", smbstate or "неизвестная ошибка")
  end

  local results = {}

  -- Проверка MS17-010 (EternalBlue)
  local status1, result1 = smb.check_ms17_010(smbstate)
  if status1 and result1 == true then
    table.insert(results, "Уязвим для MS17-010 (EternalBlue)")
    vuln_report.state = vulns.STATE.VULN
  end

  -- Проверка SMBGhost
  local status2, result2 = smb.check_smbghost(smbstate)
  if status2 and result2 == true then
    table.insert(results, "Уязвим для CVE-2020-0796 (SMBGhost)")
    vuln_report.state = vulns.STATE.VULN
  end

  -- Проверка CVE-2017-0143
  local status3, result3 = smb.check_cve_2017_0143(smbstate)
  if status3 and result3 == true then
    table.insert(results, "Уязвим для CVE-2017-0143 (SMB RCE)")
    vuln_report.state = vulns.STATE.VULN
  end

  -- Проверка SMB Signing
  if smbstate.signing_required == false then
    table.insert(results, "SMB Signing отключен (может быть перехвачен)")
  end

  -- Проверка Null Session
  if smbstate.anonymous_login == true then
    table.insert(results, "Гостевой доступ (null session) разрешён")
  end

  if #results == 0 then
    table.insert(results, "Уязвимости не обнаружены")
  end

  vuln_report.extra_info = table.concat(results, "\n")
  smb.disconnect(smbstate)
  return vuln_report:make_output()
end
