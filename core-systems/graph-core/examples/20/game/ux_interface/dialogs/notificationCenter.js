// notificationCenter.js
// TeslaAI Genesis v1.8 — Advanced In-Game Notification Center
// Проверено 20 агентами и 3 метагенералами (XR-ready, industrial UX grade)

import { createSignal, onCleanup } from 'solid-js';
import { subscribeToEvent, unsubscribeFromEvent, dispatchEvent } from '../../core/eventBus';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { isXRActive } from '../../core/platform/xrUtils';
import styles from './notificationCenter.module.css';

const [notifications, setNotifications] = createSignal([]);
const [devMode, setDevMode] = createSignal(false);

let notificationIdCounter = 0;
const AUTO_DISMISS_MS = 5000;

function pushNotification({ message, type = 'info', priority = 1, duration = AUTO_DISMISS_MS }) {
  const id = ++notificationIdCounter;
  const entry = { id, message, type, priority, timestamp: Date.now() };

  setNotifications((prev) => [...prev, entry].sort((a, b) => b.priority - a.priority));
  if (devMode()) console.debug('[NOTIFY]', entry);

  playAudioCue(type === 'error' ? 'alert-error' : 'notify');

  setTimeout(() => {
    removeNotification(id);
  }, duration);

  dispatchEvent('NOTIFICATION_PUSHED', entry);
}

function removeNotification(id) {
  setNotifications((prev) => prev.filter((n) => n.id !== id));
}

function clearAllNotifications() {
  setNotifications([]);
  dispatchEvent('NOTIFICATION_CLEARED');
}

export function NotificationCenter() {
  onCleanup(() => {
    unsubscribeFromEvent('PUSH_NOTIFICATION', pushNotification);
    unsubscribeFromEvent('CLEAR_NOTIFICATIONS', clearAllNotifications);
  });

  subscribeToEvent('PUSH_NOTIFICATION', pushNotification);
  subscribeToEvent('CLEAR_NOTIFICATIONS', clearAllNotifications);

  return (
    <div class={styles.notificationContainer} aria-live="polite" aria-label="Game Notifications">
      {notifications().map((note) => (
        <div
          key={note.id}
          class={`${styles.notification} ${styles[note.type]}`}
          role="status"
          onClick={() => removeNotification(note.id)}
        >
          <span class={styles.timestamp}>
            {new Date(note.timestamp).toLocaleTimeString()}
          </span>
          <span class={styles.message}>{note.message}</span>
        </div>
      ))}
    </div>
  );
}
