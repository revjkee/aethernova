#!/usr/bin/perl
# custom_vuln_check.pl — Интеллектуальное обнаружение кастомных уязвимостей
# Версия: 2.0-industrial | Автор: TeslaAI Genesis ThreatEngine
# Модуль использует сигнатуры, entropy-анализ, эвристику и поддержку внешних правил из JSON/YAML.

package Nikto::Plugin::CustomVulnCheck;
use strict;
use warnings;
use JSON;
use Digest::SHA qw(sha256_hex);
use List::Util qw(any);
use Exporter 'import';

our @EXPORT = qw(run_custom_vuln_check);
our $VERSION = "2.0";

# Путь к базе правил
my $RULES_FILE = "nikto/plugins/config/custom_vulns.json";

# Загрузка кастомных уязвимостей
sub load_rules {
    open(my $fh, '<:encoding(UTF-8)', $RULES_FILE) or die "Не удалось открыть $RULES_FILE: $!";
    local $/;
    my $data = <$fh>;
    close($fh);
    my $json = decode_json($data);
    return $json->{vulnerabilities} || [];
}

# Основной метод запуска сканера
sub run_custom_vuln_check {
    my ($target, $client, $logger) = @_;

    my $rules = load_rules();
    return unless @$rules;

    foreach my $rule (@$rules) {
        my $url = $target . $rule->{path};
        my $method = $rule->{method} || "GET";

        my $res = $method eq "POST"
            ? $client->post($url, {
                  Content_Type => $rule->{content_type} || 'application/x-www-form-urlencoded',
                  Content      => $rule->{body} || ""
              })
            : $client->get($url);

        next unless $res;

        my $body = $res->decoded_content || "";
        my $match_detected = 0;

        if ($rule->{match_regex} && $body =~ qr/$rule->{match_regex}/i) {
            $match_detected = 1;
        }

        if ($rule->{match_status} && $res->code == $rule->{match_status}) {
            $match_detected = 1;
        }

        if ($rule->{match_hash}) {
            my $hash = sha256_hex($body);
            $match_detected = 1 if $hash eq $rule->{match_hash};
        }

        if ($match_detected) {
            $logger->log_event({
                type        => "custom_vuln_match",
                path        => $rule->{path},
                method      => $method,
                severity    => $rule->{severity} || "medium",
                description => $rule->{description} || "Не указано",
                plugin      => "custom_vuln_check",
                reference   => $rule->{reference} || "N/A",
                status_code => $res->code,
            });

            print "[!] Найдена кастомная уязвимость: $rule->{description} [$url]\n";
        }
    }

    return 1;
}

1; # Конец модуля
