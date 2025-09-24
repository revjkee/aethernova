#!/usr/bin/perl
#
# Plugin: check_ssti.pl
# Purpose: Detect Server-Side Template Injection (SSTI) vulnerabilities via template expression probing
# Author: TeslaAI Offensive Security Consilium
# Version: 2.0-industrial
# License: TeslaAI Secure License v1.3
# Updated: 2025-07-25

package nikto::plugins::injection::check_ssti;

use strict;
use warnings;
use URI::Escape;
use Digest::SHA qw(sha256_hex);
use HTTP::Request;
use Time::HiRes qw(gettimeofday tv_interval);

sub run_check_ssti {
    my ($target_url, $http_client, $logger) = @_;

    return unless $target_url;

    my @payloads = (
        '{{7*7}}',                           # Jinja2
        '${{7*7}}',                          # Velocity / Spring
        '${{7+7}}',                          # JSP EL
        '${{7-7}}',                          # Java EL
        '{{7+7}}',                           # Twig
        '<%= 7 * 7 %>',                      # ERB
        '${{1337+1}}',                       # FreeMarker
        '#set($a=7*7) $a',                   # Velocity
    );

    my @expected = ('49', '14', '0', '1338');

    my $test_id = substr(sha256_hex(rand . time), 0, 12);
    my $vuln_detected = 0;

    foreach my $payload (@payloads) {
        my $encoded = uri_escape($payload);
        my $uri = URI->new($target_url);
        $uri->query("q=$encoded");

        my $req = HTTP::Request->new(GET => $uri);
        $req->header('X-SSTI-Test' => $test_id);

        my $start = [gettimeofday];
        my $res = $http_client->request($req);
        my $elapsed = tv_interval($start, [gettimeofday]);

        if ($res->is_success) {
            my $content = $res->decoded_content;

            foreach my $match (@expected) {
                if ($content =~ /\b$match\b/) {
                    $logger->log_event({
                        type        => 'vuln',
                        plugin      => 'check_ssti',
                        path        => $uri->as_string,
                        severity    => 'critical',
                        description => "SSTI vulnerability detected (payload: $payload, output: $match)",
                        fingerprint => $test_id,
                        method      => 'GET',
                        latency     => sprintf("%.3f", $elapsed),
                        reference   => 'CWE-1336'
                    });
                    $vuln_detected = 1;
                    last;
                }
            }
        }

        last if $vuln_detected;
    }

    return $vuln_detected;
}

1;
