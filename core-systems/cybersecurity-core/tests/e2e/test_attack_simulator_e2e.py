# filepath: cybersecurity-core/tests/e2e/test_attack_simulator_e2e.py
"""
Промышленный e2e-набор проверок для attack-simulator.

ОСНОВНЫЕ ИСТОЧНИКИ (официальные и проверяемые):
- Kubernetes API, dry-run (server-side) и audit:
  * API Concepts / DryRun: https://kubernetes.io/docs/reference/using-api/api-concepts/
  * kubectl conventions (--dry-run): https://kubernetes.io/docs/reference/kubectl/conventions/
  * Audit Logging: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
  * RBAC: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  * Kubelet authN/authZ и порты: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/
  * Ports & Protocols (10250): https://kubernetes.io/docs/reference/networking/ports-and-protocols/
- MITRE ATT&CK:
  * Containers matrix: https://attack.mitre.org/matrices/enterprise/containers/
  * T1610 Deploy Container: https://attack.mitre.org/techniques/T1610/
  * T1611 Escape to Host: https://attack.mitre.org/techniques/T1611/
  * T1613 Discovery: https://attack.mitre.org/techniques/T1613/
  * T1543.005 Persistence via container service: https://attack.mitre.org/techniques/T1543/005/
  * T1496 Resource Hijacking: https://attack.mitre.org/techniques/T1496/
  * T1041 Exfiltration Over C2: https://attack.mitre.org/techniques/T1041/
- Microsoft Azure (официальные SDK и сервисы):
  * DefaultAzureCredential: https://learn.microsoft.com/azure/developer/python/sdk/azure-identity-readme
  * ResourceManagementClient (ARM): https://learn.microsoft.com/azure/developer/python/sdk/azure-mgmt-resource-readme
  * SubscriptionClient: https://learn.microsoft.com/azure/developer/python/sdk/azure-mgmt-subscription-readme
  * What-If (ARM): https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-what-if
  * Azure Monitor Logs (LogsQueryClient, KQL): https://learn.microsoft.com/azure/developer/python/sdk/azure-monitor-query-readme
  * Network Security Groups overview: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview

Принцип безопасности тестов:
- Тесты не модифицируют инфраструктуру.
- K8s-профиль проверяется как файл (YAML) на корректность безопасных флагов.
- Azure-часть — «smoke»-уровень и мок/скипы, без реальных вызовов без явной настройки.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

import pytest

try:
    import yaml  # PyYAML
except Exception as _e:  # pragma: no cover
    pytest.skip("PyYAML не установлен: pip install pyyaml", allow_module_level=True)


# --------------------------- Утилиты пути/загрузки ---------------------------

@pytest.fixture(scope="session")
def repo_root() -> Path:
    """
    Определяет корень репозитория. Приоритет:
    1) env CYBERSEC_CORE_ROOT
    2) подъем от текущего файла до обнаружения каталога 'cybersecurity-core'
    """
    env = os.getenv("CYBERSEC_CORE_ROOT")
    if env:
        p = Path(env).resolve()
        assert p.exists(), f"CYBERSEC_CORE_ROOT не существует: {p}"
        return p

    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / "cybersecurity-core").exists():
            return parent
    # По умолчанию — два уровня вверх
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def k8s_profile_path(repo_root: Path) -> Path:
    """
    Возвращает путь к профилю Kubernetes-эмуляции.
    Сопоставлено ранее указанному расположению:
      cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/profiles/kubernetes_cluster.yaml
    """
    candidate = (
        repo_root
        / "cybersecurity-core"
        / "cybersecurity"
        / "adversary_emulation"
        / "attack_simulator"
        / "profiles"
        / "kubernetes_cluster.yaml"
    )
    if not candidate.exists():
        pytest.skip(f"Профиль не найден: {candidate}")
    return candidate


def _yaml_load(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# --------------------------- Проверки профиля K8s ---------------------------

@pytest.mark.k8s_profile
def test_k8s_profile_file_exists(k8s_profile_path: Path) -> None:
    """
    Факт: файл профиля должен существовать.
    Подтверждение: тривиальная проверка наличия файла.
    """
    assert k8s_profile_path.exists(), "Файл профиля Kubernetes отсутствует"


@pytest.mark.k8s_profile
def test_k8s_profile_safety_defaults(k8s_profile_path: Path) -> None:
    """
    Факты и источники:
    - Server-side dry-run безопасно: объект валидируется/пропускается через admission без сохранения (K8s API Concepts).
      https://kubernetes.io/docs/reference/using-api/api-concepts/
    - Практика kubectl --dry-run (server): https://kubernetes.io/docs/reference/kubectl/conventions/
    - В проде практики запрещают произвольные симуляции без явного разрешения.

    Утверждения:
    - dangerous_actions по умолчанию False.
    - dry_run_strategy == 'server'.
    - require_confirmation_for_apply == True (вводная политика).
    - deny_on_production_label == True.
    """
    doc = _yaml_load(k8s_profile_path)
    safety = doc.get("safety", {})
    assert safety.get("dangerous_actions") is False, "Ожидалось dangerous_actions: false"
    assert safety.get("dry_run_strategy") == "server", "Ожидался server-side dry-run"
    assert safety.get("require_confirmation_for_apply") is True, "Ожидалось требование подтверждения для apply"
    assert safety.get("deny_on_production_label") is True, "Ожидался запрет исполнения при env=prod"


@pytest.mark.k8s_profile
def test_k8s_profile_exec_steps_have_dry_run_flags(k8s_profile_path: Path) -> None:
    """
    Факт: Все потенциальные «мутации» должны идти через server-side dry-run по умолчанию.
    Источники: API Concepts / kubectl conventions (ссылки выше).

    Утверждение:
    - Каждый шаг с exec.action == 'apply' должен содержать flags.dry_run (bool или шаблон)
      и/или server_side_apply == True.
    """
    doc = _yaml_load(k8s_profile_path)
    stages = doc.get("stages", [])
    missing: List[str] = []
    for stage in stages:
        for step in stage.get("steps", []):
            exec_spec = step.get("exec")
            if not exec_spec:
                continue
            if exec_spec.get("action") == "apply":
                flags = exec_spec.get("flags", {})
                # допускаем строковые шаблоны вида "{{ not .safety.dangerous_actions }}"
                has_dry = "dry_run" in flags
                has_ssa = flags.get("server_side_apply") is True
                if not (has_dry or has_ssa):
                    missing.append(step.get("id", "<no-id>"))
    assert not missing, f"Отсутствует dry_run/server_side_apply в шагах: {missing}"


@pytest.mark.k8s_profile
def test_k8s_profile_environment_defaults_are_benign(k8s_profile_path: Path) -> None:
    """
    Факты и источники:
    - Образ pause из registry.k8s.io минимален и безопасен для бенчмаркинга/«пустых» контейнеров.
      (Неофициальные страницы меняются; конкретная гарантия безопасности образа не даётся —
       поэтому формулируем как общепринятую практику. Не могу подтвердить это универсально.)
    - Небольшие requests/limits минимизируют воздействие.

    Утверждения:
    - benign_test_image указывает на 'registry.k8s.io/pause' по умолчанию.
    - cpu/memory по умолчанию малы (<=50m, <=64Mi).
    """
    doc = _yaml_load(k8s_profile_path)
    env = doc.get("environment", {})
    benign = env.get("benign_test_image", "")
    if isinstance(benign, str):
        assert "registry.k8s.io/pause" in benign, "Ожидался образ pause для безвредных проверок (best practice). Не могу подтвердить это, если указан иной образ."
    res = env.get("resources", {})
    # допускаем строковые значения '50m', '64Mi'
    cpu = str(res.get("cpu", ""))
    mem = str(res.get("memory", ""))
    # простая проверка вхождения
    assert cpu.endswith("m") and int(cpu.rstrip("m")) <= 50, f"Ожидался cpu<=50m, получено {cpu or 'пусто'}"
    assert mem.lower().endswith("mi") and int(mem[:-2]) <= 64, f"Ожидалась memory<=64Mi, получено {mem or 'пусто'}"


@pytest.mark.k8s_profile
def test_k8s_profile_mitre_annotations_present(k8s_profile_path: Path) -> None:
    """
    Факт: профиль должен явно маппить тактики/техники на MITRE ATT&CK (Containers/Enterprise).
    Источники: официальный сайт MITRE ATT&CK (ссылки в header этого файла).

    Утверждения:
    - В annotations присутствуют ссылки на ключевые техники (T1610, T1613, T1543.005, T1496, T1041).
    """
    doc = _yaml_load(k8s_profile_path)
    ann = (doc.get("annotations") or {}) if isinstance(doc.get("annotations"), dict) else {}
    text = json.dumps(ann)
    required = ["T1610", "T1613", "T1543/005", "T1496", "T1041"]
    missing = [t for t in required if t not in text]
    assert not missing, f"Отсутствуют ссылки на техники MITRE: {missing}"


# --------------------------- Azure smoke/e2e (безопасные) ---------------------------

AZURE_AVAILABLE = importlib.util.find_spec("azure") is not None

pytestmark = pytest.mark.skipif(
    not AZURE_AVAILABLE, reason="Пакеты Azure SDK не установлены; см. Microsoft Learn ссылки в заголовке."
)


@pytest.mark.azure
def test_azure_integration_init_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Факты и источники:
    - DefaultAzureCredential — официальный рекомендованный путь аутентификации SDK (Microsoft Learn).
    - Конфигурация должна быть безопасной по умолчанию (dry_run=True).

    Утверждения:
    - При отсутствии AZURE_DRY_RUN в env модуль конфигурирует dry_run=True.
    """
    # импортируем только при наличии SDK
    from cybersecurity.core.adversary_emulation.integrations.cloud.azure import (  # type: ignore
        AzureConfig,
        AzureIntegration,
    )  # noqa: E402

    monkeypatch.delenv("AZURE_DRY_RUN", raising=False)
    cfg = AzureConfig.from_env()
    assert cfg.dry_run is True, "Ожидалось dry_run=True по умолчанию"

    integ = AzureIntegration(cfg)
    assert integ.config.dry_run is True, "Интеграция должна стартовать в безопасном режиме"


@pytest.mark.azure
def test_azure_kql_builder_contains_activity_table() -> None:
    """
    Факт: В типичных пайплайнах аудитных событий используется AzureActivity (часто встречаемая таблица).
    Источник: Microsoft Learn по Azure Monitor / KQL; названия таблиц зависят от настройки пайплайна.
    Не могу подтвердить это универсально для всех тенантов — тест проверяет только наличие строки в билдере.
    """
    from cybersecurity.core.adversary_emulation.integrations.cloud.azure import (  # type: ignore
        AzureIntegration,
    )  # noqa: E402

    kql = AzureIntegration.kql_recent_deployments()
    assert isinstance(kql, str) and "AzureActivity" in kql, "Ожидалась таблица AzureActivity в примере KQL (может отличаться в вашей схеме данных)"


@pytest.mark.azure
def test_azure_summarize_what_if_changes() -> None:
    """
    Факт: What-If (ARM) не применяет изменения, а возвращает прогноз (Microsoft Learn: deploy-what-if).
    Утверждение:
    - summarize_what_if_changes корректно обрабатывает результат и возвращает список словарей с полями changeType/resourceId.
    """
    from cybersecurity.core.adversary_emulation.integrations.cloud.azure import (  # type: ignore
        AzureIntegration,
    )  # noqa: E402

    class FakeChangeType:
        def __init__(self, value: str) -> None:
            self.value = value

    fake_result = SimpleNamespace(
        changes=[
            SimpleNamespace(change_type=FakeChangeType("Create"), resource_id="/subs/xxx/rg/rg1/providers/Microsoft.X/y/z"),
            SimpleNamespace(change_type=FakeChangeType("Modify"), resource_id="/subs/xxx/rg/rg1/providers/Microsoft.A/b/c"),
        ]
    )
    out = AzureIntegration.summarize_what_if_changes(fake_result)
    assert isinstance(out, list) and len(out) == 2
    assert out[0]["changeType"] == "Create" and "resourceId" in out[0]
    assert out[1]["changeType"] == "Modify" and "resourceId" in out[1]


# --------------------------- Метки и выборочное выполнение ---------------------------

def pytest_addoption(parser: pytest.Parser) -> None:  # pragma: no cover
    parser.addoption(
        "--run-azure-smoke",
        action="store_true",
        default=False,
        help="Запуск Azure smoke-тестов, если установлен Azure SDK",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:  # pragma: no cover
    run_az = config.getoption("--run-azure-smoke")
    skip_az = pytest.mark.skip(reason="Пропуск Azure smoke без флага --run-azure-smoke")
    for item in items:
        if "azure" in item.keywords and not run_az:
            item.add_marker(skip_az)
