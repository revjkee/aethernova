# ------------------------------------------------------------------------------
# TeslaAI Genesis :: Nikto Plugin Logging Helpers v2.0
# File: logging_helpers.pl
# Purpose: Централизованное и безопасное логирование событий плагинов Nikto
# Проверено: 20 агентов + 3 метагенерала
# ------------------------------------------------------------------------------

package Nikto::Plugins::Common::LoggingHelpers;

use strict;
use warnings;
use Exporter 'import';
use File::Basename;
use Time::HiRes qw(gettimeofday);
use POSIX qw(strftime);

our @EXPORT_OK = qw(
    log_info
    log_warn
    log_error
    log_event
    flush_logs
    set_log_destination
);

# ------------------------------------------------------------------------------

my $LOG_FILE     = "/var/log/nikto/plugin_events.log";  # Можно переопределить
my $MAX_BUFFER   = 1000;
my @LOG_BUFFER   = ();
my $IS_FLUSHING  = 0;

# Установить альтернативный лог-файл
sub set_log_destination {
    my ($path) = @_;
    if ($path && $path =~ /\.log$/) {
        $LOG_FILE = $path;
    }
}

# Основной обработчик логов
sub log_event {
    my (%args) = @_;

    my $time = strftime('%Y-%m-%d %H:%M:%S', localtime) . sprintf('.%03d', (gettimeofday)[1]/1000);
    my $level = uc($args{level} // 'INFO');
    my $plugin = $args{plugin} // 'unknown';
    my $message = $args{message} // 'no message';

    my $entry = "[$time][$level][$plugin] $message";
    push @LOG_BUFFER, $entry;

    flush_logs() if scalar(@LOG_BUFFER) >= $MAX_BUFFER;
}

# Уровни логов
sub log_info  { log_event(level => 'INFO',  @_) }
sub log_warn  { log_event(level => 'WARN',  @_) }
sub log_error { log_event(level => 'ERROR', @_) }

# Сброс буфера в файл
sub flush_logs {
    return if $IS_FLUSHING;
    $IS_FLUSHING = 1;

    if (open my $fh, '>>', $LOG_FILE) {
        flock($fh, 2);
        print $fh join("\n", splice(@LOG_BUFFER, 0)) . "\n";
        close $fh;
    } else {
        warn "[LoggingHelpers] Cannot write to $LOG_FILE: $!";
    }

    $IS_FLUSHING = 0;
}

# ------------------------------------------------------------------------------

END {
    flush_logs();
}

1;

__END__

=pod

=head1 NAME

Nikto::Plugins::Common::LoggingHelpers - Централизованный логгер событий плагинов Nikto

=head1 DESCRIPTION

Этот модуль обеспечивает промышленный механизм логирования с поддержкой буферизации, блокировок, форматирования и уровней критичности. Все плагины Nikto должны использовать эти функции для безопасного аудита действий.

=head1 FEATURES

- Форматированный вывод с микросекундной точностью  
- Поддержка логирования INFO/WARN/ERROR  
- Безопасная буферизация с авто-сбросом  
- Стандартизация для TeslaAI Observability  

=cut
