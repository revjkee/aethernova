# platform-security/genius-core-security/defense/sandbox.py

import os
import subprocess
import tempfile
import uuid
import shutil
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger("Sandbox")

class SandboxSession:
    def __init__(self, code: str, lang: str = "python", time_limit: int = 5):
        self.session_id = str(uuid.uuid4())
        self.code = code
        self.lang = lang
        self.time_limit = time_limit
        self.start_time = datetime.utcnow().isoformat()
        self.output = ""
        self.error = ""
        self.status = "initialized"
        self.workdir = tempfile.mkdtemp(prefix=f"sandbox_{self.session_id}_")

    def cleanup(self):
        try:
            shutil.rmtree(self.workdir)
            logger.debug(f"Окружение {self.session_id} очищено")
        except Exception as e:
            logger.warning(f"Ошибка при очистке окружения: {e}")

    def to_report(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "status": self.status,
            "output": self.output,
            "error": self.error,
            "started_at": self.start_time
        }


class Sandbox:
    def __init__(self):
        self.active_sessions: Dict[str, SandboxSession] = {}

    def execute_code(self, code: str, lang: str = "python", time_limit: int = 5) -> Dict[str, Any]:
        session = SandboxSession(code, lang, time_limit)
        self.active_sessions[session.session_id] = session

        try:
            logger.info(f"Запуск сессии sandbox {session.session_id} (язык: {lang})")

            file_path = os.path.join(session.workdir, f"code.{lang}")
            with open(file_path, "w") as f:
                f.write(session.code)

            if lang == "python":
                cmd = ["python3", file_path]
            elif lang == "bash":
                cmd = ["bash", file_path]
            else:
                session.status = "failed"
                session.error = f"Неподдерживаемый язык: {lang}"
                return session.to_report()

            result = subprocess.run(
                cmd,
                cwd=session.workdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=session.time_limit,
                text=True,
                check=False
            )

            session.output = result.stdout
            session.error = result.stderr
            session.status = "completed" if result.returncode == 0 else "error"

        except subprocess.TimeoutExpired:
            session.status = "timeout"
            session.error = "Превышено время выполнения"
        except Exception as e:
            session.status = "exception"
            session.error = str(e)
        finally:
            logger.debug(f"Сессия завершена: {session.session_id}")
            session.cleanup()
            del self.active_sessions[session.session_id]

        return session.to_report()
