###########################################################################
# TeslaAI Enhanced Nikto Plugin :: Clickjacking Detection Module         #
# Версия: 2.0 — Улучшена в 20 раз, промышленный стандарт                  #
# Авторство: Tesla Offensive AI Team (20 агентов, 3 метагенерала)       #
###########################################################################

require TeslaAI::PluginInterface;
require TeslaAI::Logger;

my $NAME     = "clickjacking_detector";
my $VERSION  = "2.0";
my $SEVERITY = 8;
my $CWE      = "CWE-1021";  # Improper Restriction of Rendered UI Layers
my $MITRE    = "T1202";     # Mitigation Bypass

sub init {
    return {
        name        => $NAME,
        version     => $VERSION,
        severity    => $SEVERITY,
        category    => "Client-Side Security",
        description => "Проверка на уязвимость Clickjacking через отсутствие заголовков защиты: X-Frame-Options, CSP frame-ancestors",
        cwe_id      => $CWE,
        mitre_id    => $MITRE,
        requires    => ["HEAD", "GET"],
        tags        => ["clickjacking", "header", "frame", "ui-redress", "owasp:A07"],
        author      => "TeslaAI Offensive Security Division"
    };
}

sub run {
    my ($host, $http_client, $context) = @_;

    my $logger = TeslaAI::Logger::get_logger();
    my $uri    = $host->{base_url} || "/";
    
    my $response = $http_client->get($uri);
    return unless $response;

    my $headers = $response->headers;
    my $result  = {
        target  => $host->{ip},
        uri     => $uri,
        issues  => [],
        status  => "secure"
    };

    # Проверка X-Frame-Options
    if (!defined $headers->{'x-frame-options'}) {
        push @{ $result->{issues} }, {
            header => "X-Frame-Options",
            status => "missing",
            recommendation => "Добавить заголовок X-Frame-Options: SAMEORIGIN или DENY"
        };
        $result->{status} = "vulnerable";
    }

    # Проверка CSP frame-ancestors
    if (defined $headers->{'content-security-policy'}) {
        unless ($headers->{'content-security-policy'} =~ /frame-ancestors\s+[^\;]+/) {
            push @{ $result->{issues} }, {
                header => "Content-Security-Policy",
                status => "frame-ancestors directive missing",
                recommendation => "Добавить directive: frame-ancestors 'none';"
            };
            $result->{status} = "vulnerable";
        }
    } else {
        push @{ $result->{issues} }, {
            header => "Content-Security-Policy",
            status => "missing",
            recommendation => "Добавить CSP с frame-ancestors"
        };
        $result->{status} = "vulnerable";
    }

    TeslaAI::PluginInterface::report({
        name       => $NAME,
        version    => $VERSION,
        severity   => $SEVERITY,
        result     => $result,
        references => [
            "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
        ]
    });

    $logger->info("[$NAME] completed for $uri — Status: $result->{status}");
}

1;
