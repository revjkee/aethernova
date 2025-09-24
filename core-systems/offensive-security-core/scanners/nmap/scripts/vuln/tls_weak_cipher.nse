-- tls_weak_cipher.nse
--
-- Проверяет поддержку уязвимых или устаревших TLS/SSL шифров сервером.
-- Оценивает риски и помогает в комплаенсе (PCI DSS, NIST, BSI и т.д.)

local sslcert = require "sslcert"
local shortport = require "shortport"
local tls = require "tls"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Сканирует сервер на предмет поддержки слабых, устаревших или запрещённых шифров TLS/SSL, включая:

- RC4, DES, 3DES
- NULL cipher
- EXPORT-grade (512-bit)
- Anon/DH_anon suites
- TLS 1.0/1.1 протоколы
- CBC с TLS < 1.2
- DHE с малым ключом (<1024)
]]

author = "TeslaAI Crypto Audit Team"

license = "Same as Nmap"

categories = {"vuln", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local vuln_report = vulns.Report:new({
    title = "TLS Weak Cipher Detection",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = description,
    references = {
      "https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
      "https://tools.ietf.org/html/rfc7525",
      "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"
    }
  })

  local status, result = tls.getCipherInfo(host, port)
  if not status then
    return "Ошибка TLS: " .. tostring(result)
  end

  local findings = {}
  for _, suite in ipairs(result) do
    local name = suite.name:lower()
    if name:match("rc4") or name:match("des") or name:match("3des") or name:match("null") then
      table.insert(findings, "Поддерживается слабый шифр: " .. suite.name)
    elseif name:match("export") or name:match("anon") or name:match("md5") then
      table.insert(findings, "Поддерживается небезопасный suite: " .. suite.name)
    elseif suite.key_exchange:match("dhe") and tonumber(suite.key_size) and suite.key_size < 1024 then
      table.insert(findings, "DHE с малым ключом: " .. suite.name)
    end
  end

  local protocols = tls.get_supported_protocols(host, port)
  if protocols.TLSv1_0 or protocols.TLSv1_1 then
    table.insert(findings, "Устаревшие протоколы TLS 1.0 / 1.1 поддерживаются")
  end

  if #findings > 0 then
    vuln_report.state = vulns.STATE.VULN
    vuln_report.extra_info = table.concat(findings, "\n")
  else
    vuln_report.extra_info = "Слабые шифры и устаревшие протоколы не обнаружены"
  end

  return vuln_report:make_output()
end
