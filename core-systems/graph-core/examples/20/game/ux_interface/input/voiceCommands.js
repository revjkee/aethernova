// voiceCommands.js
// TeslaAI Genesis v1.8 — Industrial Voice Command System
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { logVoiceEvent } from '../../core/devtools/inputLogger';
import { normalizeCommand, rejectNoise, confidenceThreshold } from './voiceUtils';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { getVoiceDictionary } from '../../core/config/commands';

const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

let recognizer = null;
let active = false;
let devMode = false;
let buffer = [];

const MAX_BUFFER = 20;
const DEFAULT_LANG = 'en-US';
const AUTO_RESTART = true;

function initRecognizer() {
  recognizer = new SpeechRecognition();
  recognizer.continuous = true;
  recognizer.interimResults = false;
  recognizer.lang = DEFAULT_LANG;

  recognizer.onresult = (event) => {
    for (const res of event.results) {
      const transcript = res[0].transcript.trim().toLowerCase();
      const confidence = res[0].confidence;

      if (confidence < confidenceThreshold) return;
      if (rejectNoise(transcript)) return;

      const command = normalizeCommand(transcript);
      const dictionary = getVoiceDictionary();

      if (dictionary[command]) {
        dispatchEvent('VOICE_COMMAND', {
          phrase: transcript,
          command: dictionary[command],
          confidence,
        });

        playAudioCue('voice-confirm');
        bufferCommand({ phrase: transcript, mapped: dictionary[command], confidence });

        if (devMode) logVoiceEvent({ type: 'command', transcript, confidence });
      } else {
        if (devMode) logVoiceEvent({ type: 'unmapped', transcript, confidence });
      }
    }
  };

  recognizer.onerror = (e) => {
    if (devMode) logVoiceEvent({ type: 'error', error: e.error });
    if (AUTO_RESTART && active) recognizer.start();
  };

  recognizer.onend = () => {
    if (AUTO_RESTART && active) recognizer.start();
  };
}

function bufferCommand(entry) {
  if (buffer.length >= MAX_BUFFER) buffer.shift();
  buffer.push({ ...entry, timestamp: Date.now() });
}

export function enableVoiceCommands({ language = DEFAULT_LANG, developerMode = false } = {}) {
  if (!SpeechRecognition) throw new Error('SpeechRecognition API not supported in this browser');

  devMode = developerMode;
  active = true;

  initRecognizer();
  recognizer.lang = language;
  recognizer.start();

  subscribeToEvent('VOICE_COMMAND_STOP', disableVoiceCommands);
  subscribeToEvent('VOICE_COMMAND_RELOAD', reloadDictionary);
}

export function disableVoiceCommands() {
  active = false;
  if (recognizer) recognizer.stop();
  recognizer = null;
  buffer = [];
}

function reloadDictionary() {
  // Резерв для будущей динамической подгрузки
}

export function getVoiceCommandBuffer() {
  return [...buffer];
}
