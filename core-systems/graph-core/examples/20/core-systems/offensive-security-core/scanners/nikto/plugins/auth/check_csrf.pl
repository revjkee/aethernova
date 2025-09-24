#!/usr/bin/perl
#
# check_csrf.pl — Проверка на наличие уязвимости CSRF
# Версия: 2.0-industrial
# MITRE: CWE-352, CWE-664
# TeslaAI Offensive Core Plugin Interface

use strict;
use warnings;
use TeslaAI::Logger qw(log_info log_warn log_error);
use TeslaAI::PluginInterface;
use TeslaAI::Utils qw(extract_forms extract_cookies);

sub init {
    return {
        name        => "Cross-Site Request Forgery (CSRF)",
        author      => "TeslaAI Offensive Core",
        version     => "2.0-industrial",
        description => "Обнаружение веб-форм, уязвимых к атакам Cross-Site Request Forgery",
        mitre       => ["CWE-352"],
        type        => "auth",
        severity    => "high",
        tags        => ["csrf", "auth", "session", "browser"],
        profile     => ["full", "compliance"]
    };
}

sub run {
    my ($host, $http_client, $context) = @_;

    my $res = $http_client->get($host . "/");
    return unless $res->is_success;

    my @forms = extract_forms($res->content);
    log_info("Обнаружено форм: " . scalar(@forms));

    foreach my $form (@forms) {
        my $action     = $form->{action}     || "/";
        my $method     = uc($form->{method} || "GET");
        my $inputs     = $form->{inputs}     || {};
        my $csrf_token = detect_csrf_token($inputs);

        my $cookies = extract_cookies($res->headers);
        my $csrf_cookie = detect_csrf_cookie($cookies);

        # Проверка отсутствия токена и куки без защиты
        if (!$csrf_token && (!$csrf_cookie || !$csrf_cookie->{samesite})) {
            report($host, "Форма без CSRF токена и куки без SameSite", $form, $cookies);
        }

        # Проверка на слабый токен (низкая энтропия, короткий длины)
        if ($csrf_token && length($csrf_token->{value}) < 10) {
            report($host, "CSRF токен подозрительно короткий", $form, $cookies);
        }
    }
}

sub detect_csrf_token {
    my ($inputs) = @_;
    foreach my $name (keys %$inputs) {
        if ($name =~ /csrf|token|auth|nonce/i) {
            return { name => $name, value => $inputs->{$name} };
        }
    }
    return undef;
}

sub detect_csrf_cookie {
    my ($cookies) = @_;
    foreach my $cookie (@$cookies) {
        if ($cookie->{name} =~ /csrf|session/i) {
            return $cookie;
        }
    }
    return undef;
}

sub report {
    my ($host, $issue, $form, $cookies) = @_;

    my $report = {
        host        => $host,
        vuln_id     => "CSRF-FORM",
        status      => "confirmed",
        severity    => "high",
        description => "Обнаружена форма с недостаточной защитой от CSRF: $issue",
        form_action => $form->{action},
        method      => $form->{method},
        mitigation  => "Используйте уникальные, криптостойкие токены и атрибут SameSite=Strict/Lax в куки.",
        tags        => ["csrf", "web", "browser", "form"],
        mitre       => ["CWE-352", "CWE-664"]
    };

    log_warn("CSRF уязвимость: $issue в форме $form->{action}");
    TeslaAI::PluginInterface::submit_report($report);
}

1;
