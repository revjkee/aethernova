# THIRD_PARTY_NOTICES
Version: 2025-08-19
Status: Unverified (dependencies not scanned). I cannot verify this.

Цель:
Этот документ агрегирует уведомления, лицензии и атрибуции для третьесторонних компонентов, включённых в состав security-core, в соответствии с условиями их лицензий. Он не подтверждает фактический список зависимостей — см. раздел “Регeнерация и верификация”.

## 1. Область действия
- Источники: зависимости на уровнях исходников, сборки, контейнеров, дистрибутивов и статически/динамически линкованных библиотек.
- Форматы: исходные тексты, бинарные артефакты, контейнерные образы, вендорные снапшоты, заголовочные файлы.
- Обязательства: уведомления/копии лицензий, атрибуции, условия распространения производных, предоставление исходников (где применимо), сохранение уведомлений об авторских правах.

## 2. Регeнерация и верификация (SBOM‑driven)
Рекомендуется автоматически генерировать SBOM и перечень лицензий в CI перед релизом. Ниже — типовой, но необязательный, стек инструментов (используйте применимые вашему стеку):

- Универсально (контейнер/файловая система):
  - syft: `syft packages dir:. -o spdx-json > sbom/SBOM.spdx.json`
- Python:
  - pip-licenses: `pip-licenses --format=json --with-authors --with-urls > licenses/python.json`
- Node.js:
  - license-checker: `npx license-checker --json > licenses/node.json`
- Go:
  - go-licenses: `go-licenses report ./... > licenses/go.csv`
- Rust:
  - cargo-deny: `cargo deny list > licenses/rust.txt`
- Java:
  - cyclonedx-maven: `mvn -B -DskipTests cyclonedx:makeAggregateBom`

После генерации:
1) Сведите список в таблицу “Catalog of Components” ниже (можно автогенерацией).
2) Сохраните полные тексты лицензий в каталоге `licenses/`.
3) Включите этот файл и каталог `licenses/` в состав дистрибутива.
4) Зафиксируйте артефакты в релизе (tag) и CI‑логи.

I cannot verify this: фактические зависимости проекта не были сканированы в рамках текущего ответа.

## 3. Compliance Checklist
- [ ] Для каждого компонента указаны: название, версия, лицензия, источник (URL), правообладатели.
- [ ] Полные тексты лицензий присутствуют в `licenses/` (где это требуется).
- [ ] Выполнены условия распространения (копирайты, уведомления, изменения).
- [ ] Для copyleft‑лицензий выполнены требования предоставления исходников/patch‑сет.
- [ ] Атрибуции и особые уведомления сохранены в неизменном виде.
- [ ] SBOM приложен к релизу.

## 4. Catalog of Components (template)
| Component | Version | License | Upstream URL | Copyright |
|-----------|---------|---------|--------------|-----------|
| (fill)    | (fill)  | (SPDX)  | (fill)       | (fill)    |

Пример строки (комментарий, удалить перед релизом):
<!-- Example: libsodium | 1.0.19 | ISC | https://github.com/jedisct1/libsodium | (c) Frank Denis and contributors -->

## 5. Special Notices (use-if-present templates)
Ниже приведены шаблоны уведомлений, которые следует включать ТОЛЬКО если соответствующие компоненты действительно присутствуют в поставке.

### 5.1 OpenSSL/LibreSSL/BoringSSL Notice (use if present)
This product may include software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (https://www.openssl.org/)
This product may include cryptographic software written by Eric Young (eay@cryptsoft.com).
This product may include software written by Tim Hudson (tjh@cryptsoft.com).

### 5.2 SQLite Notice (use if present)
This product includes SQLite, which is in the public domain. https://sqlite.org

### 5.3 curl/libcurl Notice (use if present)
This product includes libcurl. Copyright (c) Daniel Stenberg, daniel@haxx.se, and many contributors. Licensed under the curl license (MIT-like).

(Удалите неактуальные секции. Добавьте другие специальные уведомления для используемых компонентов.)

## 6. License Texts (Appendix)
Полные тексты лицензий должны находиться в каталоге `licenses/`. Ниже — включённые базовые тексты для наиболее распространённых лицензий. Если в зависимостях присутствуют другие лицензии (GPL/LGPL/MPL/AGPL и т. п.), добавьте их полные тексты.

### 6.1 MIT License (Full Text)
MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

### 6.2 BSD 3-Clause License (Full Text)
BSD 3-Clause License

Copyright (c) <year>, <owner>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the <organization> nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### 6.3 ISC License (Full Text)
ISC License

Copyright (c) <year> <owner>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

### 6.4 zlib License (Full Text)
zlib License

(C) <year> <author>

This software is provided 'as-is', without any express or implied warranty.
In no event will the authors be held liable for any damages arising from the
use of this software.
Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it freely,
subject to the following restrictions:
1. The origin of this software must not be misrepresented; you must not claim
   that you wrote the original software. If you use this software in a product,
   an acknowledgment in the product documentation would be appreciated but is
   not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.

### 6.5 Apache License 2.0 (Header and Reference)
Для компонентов под Apache-2.0 необходимо включать полный текст лицензии в `licenses/Apache-2.0.txt` и сохранять NOTICE‑уведомления. Стандартный заголовок файла:

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

(Приложите полный текст Apache-2.0 к поставке. Если компонент содержит NOTICE, сохраните его в неизменном виде.)

## 7. Records and Audit
- Храните артефакты сканирования (SBOM, отчёты по лицензиям) в release‑assets.
- Поддерживайте соответствие путём регулярного пересмотра перед минорными/мажорными релизами.
- Фиксируйте изменения в CHANGELOG для юридственно значимых модификаций (лицензии, копирайты, замены компонентов).

End of THIRD_PARTY_NOTICES.
