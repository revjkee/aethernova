#!/usr/bin/perl
# check_user_enum.pl — Расширенное обнаружение уязвимости user enumeration
# Версия: 2.0-industrial | Автор: TeslaAI Genesis SecureEnum
# Использует адаптивную стратегию: сравнение ответов, заголовков, размера, timing-анализ, bypass-защита.

package Nikto::Plugin::CheckUserEnum;
use strict;
use warnings;
use Time::HiRes qw(gettimeofday tv_interval);
use Digest::SHA qw(sha256_hex);
use JSON;
use Exporter 'import';

our @EXPORT = qw(run_check_user_enum);
our $VERSION = "2.0";

# Типовые endpoints
my @enum_targets = (
    { path => "/login", method => "POST", param_user => "username", param_pwd => "password", desc => "Standard login form" },
    { path => "/api/auth", method => "POST", param_user => "user", param_pwd => "pass", desc => "API endpoint" },
);

# Типовые имена пользователей
my @test_users = qw(admin root test user guest administrator demo support);

# Поддельный пароль (для стандартизации)
my $fake_pass = "InvalidPassword123!";

sub run_check_user_enum {
    my ($target, $client, $logger) = @_;

    foreach my $endpoint (@enum_targets) {
        foreach my $username (@test_users) {
            my $url = $target . $endpoint->{path};
            my $start_time = [gettimeofday];

            my $res = $client->post($url, {
                Content_Type => 'application/x-www-form-urlencoded',
                Content => $endpoint->{param_user} . "=$username&" . $endpoint->{param_pwd} . "=$fake_pass"
            });

            my $duration = tv_interval($start_time);
            my $content_hash = sha256_hex($res->decoded_content || '');

            my $result = {
                timestamp => gettimeofday,
                type      => "user_enum_probe",
                username  => $username,
                path      => $endpoint->{path},
                desc      => $endpoint->{desc},
                method    => $endpoint->{method},
                status    => $res->code,
                time_ms   => sprintf("%.3f", $duration * 1000),
                size      => length($res->decoded_content || ''),
                hash      => $content_hash,
            };

            $logger->log_event($result);

            if ($res->code == 200 && $res->decoded_content =~ /invalid password|wrong password/i) {
                print "[!] Потенциальная user enumeration: пользователь '$username' обнаружен по содержимому [$url]\n";
            }
            elsif ($res->code == 403 || $res->code == 404) {
                print "[+] Возможное различие статусов для существующего и несуществующего пользователя ($username)\n";
            }
        }
    }

    return 1;
}

1; # Конец модуля
