#!/usr/bin/perl
# check_sensitive_files.pl — Расширенная проверка чувствительных файлов
# Версия: 2.0-industrial | Автор: TeslaAI Genesis Core
# Проверка уязвимых и забытых файлов, включая .git, .env, backup-архивы, журналирование и сигнатуры.

package Nikto::Plugin::CheckSensitiveFiles;
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use JSON;
use Time::HiRes qw(gettimeofday);
use Exporter 'import';

our @EXPORT = qw(run_check_sensitive_files);
our $VERSION = "2.0";

# Централизованный список файлов
my @sensitive_files = (
    { path => "/.git/", tags => ["leak", "high"], desc => "Git metadata directory" },
    { path => "/.env", tags => ["cred", "high"], desc => "Environment variables" },
    { path => "/backup.zip", tags => ["archive", "medium"], desc => "Backup archive file" },
    { path => "/config.old", tags => ["legacy", "low"], desc => "Old configuration file" },
    { path => "/db.sql", tags => ["dump", "high"], desc => "Raw SQL database dump" },
    { path => "/debug.log", tags => ["log", "medium"], desc => "Debugging log file" },
    { path => "/test.php", tags => ["code", "medium"], desc => "Leftover test script" },
    { path => "/phpinfo.php", tags => ["info", "critical"], desc => "Full PHP config disclosure" },
    { path => "/crossdomain.xml", tags => ["policy", "low"], desc => "Flash cross-domain policy" },
    { path => "/id_rsa", tags => ["key", "critical"], desc => "Private SSH key file" },
);

# Основная функция
sub run_check_sensitive_files {
    my ($target, $client, $logger) = @_;

    foreach my $entry (@sensitive_files) {
        my $url = $target . $entry->{path};
        my $res = $client->get($url);
        my $time = gettimeofday;

        if ($res && $res->code == 200) {
            my $sig = sha256_hex($res->decoded_content);
            $logger->log_event({
                timestamp => $time,
                type      => "sensitive_file_found",
                file      => $entry->{path},
                tags      => $entry->{tags},
                severity  => $entry->{tags}->[1] || "unknown",
                desc      => $entry->{desc},
                hash      => $sig,
                url       => $url
            });

            print "[!] Найден чувствительный файл: $entry->{path} ($entry->{desc}) [$url]\n";
        }
    }

    return 1;
}

1; # End of module
