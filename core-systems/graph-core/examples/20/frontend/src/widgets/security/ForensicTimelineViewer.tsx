import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Virtuoso } from 'react-virtuoso';
import { format, parseISO } from 'date-fns';
import { enUS, ru } from 'date-fns/locale';
import clsx from 'clsx';
import { AiOutlineReload, AiOutlineFilter, AiOutlineSearch, AiOutlineInfoCircle } from 'react-icons/ai';
import { Tooltip } from '@/shared/components/Tooltip';
import { Modal } from '@/shared/components/Modal';
import { useTheme } from '@/shared/hooks/useTheme';
import { useLocalStorage } from '@/shared/hooks/useLocalStorage';
import { SeverityBadge } from '@/widgets/Security/components/SeverityBadge';
import { exportToCSV } from '@/shared/utils/exportUtils';
import { debounce } from '@/shared/utils/debounce';
import { TimelineEvent, ForensicFilter, LocaleType } from './types';
import { fetchForensicTimeline, fetchEventDetails } from './api';
import styles from './ForensicTimelineViewer.module.css';

/**
 * ForensicTimelineViewer
 * Просмотр временных цепочек событий для анализа безопасности.
 * Поддержка:
 *  - Виртуализация списков (до 1 млн событий)
 *  - Локальная фильтрация и поиск
 *  - Экспорт в CSV
 *  - Переключение локали и формата времени
 *  - Подсветка по уровню угрозы
 *  - Просмотр подробностей события
 */

export const ForensicTimelineViewer: React.FC = () => {
  const { theme } = useTheme();
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [filteredEvents, setFilteredEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useLocalStorage<ForensicFilter>('forensic_filter', { severity: 'ALL', query: '' });
  const [locale, setLocale] = useLocalStorage<LocaleType>('forensic_locale', 'ru');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const [details, setDetails] = useState<string | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);

  const dateLocale = useMemo(() => (locale === 'ru' ? ru : enUS), [locale]);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchForensicTimeline();
      setEvents(data);
      setFilteredEvents(applyFilters(data, filter));
    } catch (err) {
      console.error('Error fetching forensic timeline:', err);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  const applyFilters = useCallback((data: TimelineEvent[], currentFilter: ForensicFilter) => {
    let result = data;
    if (currentFilter.severity !== 'ALL') {
      result = result.filter(e => e.severity === currentFilter.severity);
    }
    if (currentFilter.query.trim()) {
      const q = currentFilter.query.toLowerCase();
      result = result.filter(e => e.message.toLowerCase().includes(q) || e.source.toLowerCase().includes(q));
    }
    return result;
  }, []);

  const onSearchChange = useMemo(
    () =>
      debounce((value: string) => {
        setFilter(f => ({ ...f, query: value }));
        setFilteredEvents(applyFilters(events, { ...filter, query: value }));
      }, 300),
    [events, filter, applyFilters, setFilter]
  );

  const handleExport = () => {
    exportToCSV(filteredEvents, 'forensic_timeline_export.csv');
  };

  const handleEventClick = async (event: TimelineEvent) => {
    setSelectedEvent(event);
    try {
      const info = await fetchEventDetails(event.id);
      setDetails(info);
    } catch (err) {
      setDetails('Ошибка загрузки деталей события');
    }
  };

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  return (
    <div className={clsx(styles.wrapper, theme)}>
      <header className={styles.header}>
        <div className={styles.controls}>
          <button onClick={loadEvents} className={styles.iconButton} title="Обновить">
            <AiOutlineReload />
          </button>
          <button onClick={handleExport} className={styles.iconButton} title="Экспорт в CSV">
            ⬇
          </button>
          <select
            value={filter.severity}
            onChange={e => setFilter(f => ({ ...f, severity: e.target.value as ForensicFilter['severity'] }))}
            className={styles.select}
          >
            <option value="ALL">Все уровни</option>
            <option value="LOW">Низкий</option>
            <option value="MEDIUM">Средний</option>
            <option value="HIGH">Высокий</option>
            <option value="CRITICAL">Критический</option>
          </select>
          <select value={locale} onChange={e => setLocale(e.target.value as LocaleType)} className={styles.select}>
            <option value="ru">Русский</option>
            <option value="en">English</option>
          </select>
          <div className={styles.search}>
            <AiOutlineSearch className={styles.searchIcon} />
            <input
              ref={searchRef}
              type="text"
              placeholder="Поиск..."
              defaultValue={filter.query}
              onChange={e => onSearchChange(e.target.value)}
            />
          </div>
        </div>
      </header>

      <section className={styles.timeline}>
        {loading ? (
          <div className={styles.loader}>Загрузка...</div>
        ) : (
          <Virtuoso
            data={filteredEvents}
            itemContent={(index, event) => (
              <div
                key={event.id}
                className={clsx(styles.eventRow, styles[`severity-${event.severity.toLowerCase()}`])}
                onClick={() => handleEventClick(event)}
              >
                <div className={styles.timestamp}>
                  {format(parseISO(event.timestamp), 'dd.MM.yyyy HH:mm:ss', { locale: dateLocale })}
                </div>
                <div className={styles.source}>{event.source}</div>
                <div className={styles.message}>{event.message}</div>
                <div className={styles.severity}>
                  <SeverityBadge severity={event.severity} />
                </div>
              </div>
            )}
          />
        )}
      </section>

      {selectedEvent && (
        <Modal onClose={() => setSelectedEvent(null)} title={`Детали события ${selectedEvent.id}`}>
          <div className={styles.details}>
            {details ? <pre>{details}</pre> : <div className={styles.loader}>Загрузка деталей...</div>}
          </div>
        </Modal>
      )}

      <footer className={styles.footer}>
        <Tooltip content="Количество событий после фильтрации">
          <AiOutlineInfoCircle /> {filteredEvents.length}
        </Tooltip>
      </footer>
    </div>
  );
};
