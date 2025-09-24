# Third-Party Notices for NeuroForge Core

Этот документ содержит перечень сторонних компонентов, включённых в сборку **neuroforge-core**, и соответствующие сведения о лицензиях и атрибуции. Полные тексты лицензий воспроизводятся без изменений в каталоге `licenses/` (один файл на каждую лицензию или компонент), а также, где требуется лицензией, — upstream NOTICE.

> Внимание: чтобы избежать недостоверной информации, конкретные элементы заполняются автоматически CI-пайплайном на основе SBOM/SPDX. Все поля, отмеченные квадратными скобками, являются заполняемыми.

---

## 1) Инвентаризация зависимостей (SPDX-сводка)

Ниже представлена человечески-читаемая таблица (синхронизированная с машинно-читаемым SBOM).  
Источник истины: `sbom/spdx.spdx.json` (или `sbom/cyclonedx.json`).

| Name                          | Version | License (SPDX)      | Homepage / Source                 | Copyright                                | Files / Notes                              |
|-------------------------------|---------|---------------------|-----------------------------------|-------------------------------------------|--------------------------------------------|
| [PACKAGE_NAME]                | [X.Y.Z] | [Apache-2.0]        | [https://…]                       | [© Original Authors]                      | vendored: no; notice: yes (see below)      |
| [PACKAGE_NAME]                | [X.Y.Z] | [MIT]               | [https://…]                       | [© Original Authors]                      | vendored: no; notice: n/a                   |
| [PACKAGE_NAME]                | [X.Y.Z] | [BSD-3-Clause]      | [https://…]                       | [© Original Authors]                      | redistributed binaries: no                  |
| [PACKAGE_NAME]                | [X.Y.Z] | [MPL-2.0]           | [https://…]                       | [© Original Authors]                      | source mods: none                           |
| [PACKAGE_NAME]                | [X.Y.Z] | [LGPL-3.0-or-later] | [https://…]                       | [© Original Authors]                      | dynamically linked                          |

Машинно-читаемый блок (для инструментов), синхронизируемый CI:
```json
{
  "third_party_inventory": [
    {
      "name": "[PACKAGE_NAME]",
      "version": "[X.Y.Z]",
      "license_spdx": "[Apache-2.0|MIT|BSD-3-Clause|…]",
      "homepage": "[URL]",
      "source": "[URL or VCS]",
      "notice": true,
      "license_file": "licenses/[license-id].txt",
      "upstream_notice_file": "licenses/[package]/NOTICE"
    }
  ],
  "sbom": {
    "format": "SPDX-2.3",
    "path": "sbom/spdx.spdx.json"
  }
}
