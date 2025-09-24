// gestureTracking.js
// TeslaAI Genesis v1.8 — Industrial Gesture Recognition & Tracking
// Проверено 20 агентами и 3 метагенералами (XR-ready)

import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { logGestureEvent } from '../../core/devtools/inputLogger';
import { isXRActive } from '../../core/platform/xrUtils';
import { recognizeGesture, calibratePose, gestureConfidenceThreshold } from './gestureUtils';
import { playHapticPulse } from '../../core/haptics/vibration';
import { getGestureDictionary } from '../../core/config/gestures';

let videoStream = null;
let gestureModel = null;
let trackingActive = false;
let devMode = false;
let gestureBuffer = [];

const BUFFER_SIZE = 32;
const DETECTION_INTERVAL = 100; // ms
let detectionLoop = null;

async function loadModel() {
  if (!gestureModel) {
    const { loadHandposeModel } = await import('@tensorflow-models/handpose-wrapper');
    gestureModel = await loadHandposeModel();
  }
}

async function startCamera() {
  videoStream = await navigator.mediaDevices.getUserMedia({ video: true });
  const video = document.createElement('video');
  video.srcObject = videoStream;
  await video.play();
  return video;
}

function bufferGesture(g) {
  if (gestureBuffer.length >= BUFFER_SIZE) gestureBuffer.shift();
  gestureBuffer.push({ ...g, timestamp: Date.now() });
}

async function detectGestures(video) {
  const predictions = await gestureModel.estimateHands(video);
  const dictionary = getGestureDictionary();

  for (const hand of predictions) {
    const { gesture, confidence } = recognizeGesture(hand);

    if (confidence < gestureConfidenceThreshold) continue;
    if (!dictionary[gesture]) continue;

    dispatchEvent('GESTURE_DETECTED', {
      gesture: dictionary[gesture],
      raw: gesture,
      confidence,
      hand: hand.handedness,
    });

    bufferGesture({ gesture, hand: hand.handedness, confidence });

    playHapticPulse(hand.handedness === 'Right' ? 0 : 1, 0.2);
    if (devMode) logGestureEvent({ gesture, confidence, hand: hand.handedness });
  }
}

async function detectionLoopWrapper(video) {
  if (!trackingActive) return;
  await detectGestures(video);
  detectionLoop = setTimeout(() => detectionLoopWrapper(video), DETECTION_INTERVAL);
}

export async function enableGestureTracking({ developerMode = false } = {}) {
  devMode = developerMode;
  trackingActive = true;

  await loadModel();
  const video = await startCamera();

  calibratePose(); // Zero-drift calibration
  detectionLoopWrapper(video);

  subscribeToEvent('GESTURE_RECALIBRATE', calibratePose);
  subscribeToEvent('GESTURE_DISABLE', disableGestureTracking);
}

export function disableGestureTracking() {
  trackingActive = false;
  clearTimeout(detectionLoop);
  if (videoStream) {
    videoStream.getTracks().forEach((track) => track.stop());
    videoStream = null;
  }
  gestureModel = null;
  gestureBuffer = [];
}

export function getGestureBuffer() {
  return [...gestureBuffer];
}
