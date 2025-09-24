#!/usr/bin/perl
#
# check_cors_misconfig.pl — Проверка уязвимых CORS-настроек
# Версия: 2.0-industrial (TeslaAI Offensive Core)
# MITRE: T1133 (External Remote Services), CWE-942, CWE-346

use strict;
use warnings;
use TeslaAI::Logger qw(log_info log_warn log_error);
use TeslaAI::PluginInterface;

sub init {
    return {
        name        => "CORS Misconfiguration",
        author      => "TeslaAI Offensive Core",
        version     => "2.0-industrial",
        description => "Обнаружение CORS-настроек, позволяющих атаки типа credential leakage и origin spoofing",
        mitre       => ["T1133"],
        type        => "auth",
        severity    => "medium",
        tags        => ["cors", "auth", "origin", "privacy"],
        profile     => ["full", "compliance", "stealth"]
    };
}

sub run {
    my ($host, $http_client, $context) = @_;

    my @test_origins = (
        "http://evil.example.com",
        "null",
        "https://malicious.com",
        "http://$host.evil.org"
    );

    my $target_path = "/"; # путь для запроса (возможно, перезаписываемый через config.yaml)

    foreach my $origin (@test_origins) {
        my $res = $http_client->options($host . $target_path, {
            headers => {
                'Origin'                        => $origin,
                'Access-Control-Request-Method'=> 'GET',
                'Access-Control-Request-Headers' => 'X-Custom-Header'
            }
        });

        my $ac_allow_origin  = $res->header('Access-Control-Allow-Origin') || '';
        my $ac_allow_creds   = $res->header('Access-Control-Allow-Credentials') || '';
        my $ac_allow_headers = $res->header('Access-Control-Allow-Headers') || '';

        log_info("CORS Ответ с Origin=$origin | ACAO=$ac_allow_origin | Credentials=$ac_allow_creds");

        if ($ac_allow_origin eq '*' && $ac_allow_creds eq 'true') {
            report($host, "Wildcard + Credentials: небезопасная конфигурация", $origin, $res);
        }
        elsif ($ac_allow_origin eq $origin && $ac_allow_creds eq 'true') {
            report($host, "Origin эхо с включёнными credentials", $origin, $res);
        }
        elsif ($ac_allow_origin =~ /^http:\/\/.*evil/ && $ac_allow_creds eq 'true') {
            report($host, "CORS-политика позволяет поддомен злоумышленника", $origin, $res);
        }
    }
}

sub report {
    my ($host, $issue, $origin, $res) = @_;

    my $report = {
        host       => $host,
        vuln_id    => "CORS-MISCONFIG",
        status     => "confirmed",
        severity   => "medium",
        description=> "Обнаружена потенциально опасная CORS-конфигурация: $issue",
        origin     => $origin,
        mitigation => "Ограничить Origin строго допустимыми значениями. Отключить 'credentials' для wildcard.",
        headers    => {
            'Access-Control-Allow-Origin'      => $res->header('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Credentials' => $res->header('Access-Control-Allow-Credentials'),
        },
        mitre      => ["T1133"]
    };

    log_warn("CORS Misconfiguration обнаружена на $host ($origin)");
    TeslaAI::PluginInterface::submit_report($report);
}

1;
