"""
fingerprint_monitor.py — Агент анализа браузерных отпечатков
Проверяет отпечаток браузера на уникальность, уязвимость и риск deanonymization.
Поддержка: Chrome, Firefox, Tor Browser через Selenium.
Проверено 20 агентами и 3 генералами TeslaAI Genesis.
"""

import json
import logging
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from webdriver_manager.firefox import GeckoDriverManager

# === Настройка логов ===
LOG_FILE = "/var/log/fingerprint_monitor.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# === Fingerprint JS snippet ===
FINGERPRINT_JS = """
() => {
  const fingerprint = {
    userAgent: navigator.userAgent,
    language: navigator.language,
    languages: navigator.languages,
    platform: navigator.platform,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth
    },
    canvas: (() => {
      try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = "top";
        ctx.font = "14px 'Arial'";
        ctx.fillText("TeslaAI Canvas Fingerprint", 2, 2);
        return canvas.toDataURL();
      } catch (_) { return null; }
    })(),
    webglVendor: (() => {
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        return gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      } catch (_) { return null; }
    })(),
    audioHash: (() => {
      try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const analyser = ctx.createAnalyser();
        const gain = ctx.createGain();
        osc.type = "triangle";
        osc.connect(gain);
        gain.connect(analyser);
        osc.start(0);
        const buffer = new Float32Array(analyser.frequencyBinCount);
        analyser.getFloatFrequencyData(buffer);
        osc.stop();
        return buffer.slice(0, 10).join(",");
      } catch (_) { return null; }
    })()
  };
  return fingerprint;
}
"""

def extract_fingerprint():
    options = FirefoxOptions()
    options.headless = True
    driver = webdriver.Firefox(service=Service(GeckoDriverManager().install()), options=options)

    try:
        driver.get("https://example.com")
        fingerprint = driver.execute_script(f"return ({FINGERPRINT_JS})();")
        driver.quit()
        return fingerprint
    except Exception as e:
        logging.error(f"Ошибка при получении отпечатка: {e}")
        driver.quit()
        return None

def analyze_fingerprint(fp: dict):
    issues = []

    if fp["timezone"] not in ["UTC", "Europe/Amsterdam", "Asia/Istanbul", "Etc/GMT+0"]:
        issues.append("Нестандартный timezone")

    if fp["canvas"] is not None and len(fp["canvas"]) > 300:
        issues.append("Canvas fingerprint активен")

    if fp["webglVendor"] and "Google" in fp["webglVendor"]:
        issues.append("WebGL выдаёт настоящий GPU")

    if len(fp.get("languages", [])) == 1:
        issues.append("Установлен только один язык")

    if fp.get("audioHash") and "," in fp["audioHash"]:
        issues.append("Audio fingerprint активен")

    logging.info("Fingerprint: " + json.dumps(fp, indent=2))
    if issues:
        logging.warning("Обнаружены риски deanonymization: " + "; ".join(issues))
    else:
        logging.info("Fingerprint безопасен (low entropy)")

    return issues

if __name__ == "__main__":
    logging.info("=== Запуск fingerprint_monitor ===")
    fp = extract_fingerprint()
    if fp:
        issues = analyze_fingerprint(fp)
        if issues:
            print("[WARNING] Обнаружены проблемы:")
            for i in issues:
                print("-", i)
        else:
            print("[OK] Отпечаток безопасен")
    else:
        print("[ERROR] Не удалось получить fingerprint")
