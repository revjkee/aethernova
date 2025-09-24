// zero-trust-core/configs/policies/cedar/policies.cedar
// Версия схемы и предположения:
// - Сущности: User, Group, DeviceProfile, Application, Endpoint, Zone, Action.
// - Атрибуты контекста (поступают от PDP):
//   context.authn.aal            : Number (1..3) — уровень аутентификации (AAL).
//   context.authn.mfa_methods    : Set<String> — использованные методы ("webauthn","totp","push").
//   context.tls.client_auth      : Bool — подтвержден ли клиентский сертификат (mTLS).
//   context.tls.spiffe_id        : String? — SPIFFE ID ворклоада при mTLS.
//   context.device.profile       : String — профиль устройства ("managed_win11","managed_mac","unmanaged").
//   context.device.edr_healthy   : Bool — состояние EDR.
//   context.geo.country          : String — ISO‑код страны.
//   context.zone                 : String — логическая зона источника ("corp_lan","public_internet","vendor_vpn").
//   context.risk.score           : Number (0..100) — итоговый риск.
//   context.breakglass.valid     : Bool — активна ли утвержденная break‑glass сессия.
//   context.approval.ids         : Set<String> — ID активных утверждений (workflow).
// - Атрибуты ресурса:
//   resource.app                 : String — идентификатор приложения ("payments_api","hr_portal","git_forge").
//   resource.labels              : Set<String> — метки (например, {"admin","pci","pii","internal"}).
//   resource.sensitivity         : String — "low"|"medium"|"high".
//   Для egress (действие Action::"connect"):
//   resource.dst.domain          : String
//   resource.dst.port            : Number
//   resource.dst.category        : String — например "corporate","payments","public".
// - Группы (ERT) задают членство principal in Group::"...".
// - В Cedar forbid переопределяет любой permit.

// ------------------------------ ГЛОБАЛЬНЫЕ ЗАПРЕТЫ ----------------------------

// Гео‑блок (кроме явно разрешенных исключений уровня break-glass ниже не применяется,
// так как forbid имеет приоритет).
forbid (principal, action, resource)
when { context.geo.country in {"RU","KP","IR"} };

// Требуем клиентскую аутентификацию (mTLS) для внутренних приложений.
forbid (principal, action, resource)
when {
  resource.app in {"payments_api","hr_portal","git_forge"}
  && context.tls.client_auth == false
};

// Запрет при высоком риске.
forbid (principal, action, resource)
when { context.risk.score >= 70 };

// Карантин для неподконтрольных устройств на критичных приложениях.
forbid (principal, action, resource)
when {
  resource.app in {"payments_api","git_forge"}
  && context.device.profile == "unmanaged"
};

// Критичные операции требуют здорового EDR.
forbid (principal, action in {Action::"write", Action::"delete", Action::"admin", Action::"deploy"}, resource)
when { context.device.edr_healthy == false };

// HR‑портал: подрядчикам запрещены изменения.
forbid (principal in Group::"contractors", action in {Action::"write", Action::"delete", Action::"admin"}, resource)
when { resource.app == "hr_portal" };

// Egress по умолчанию запрещен (Zero egress). Разрешения ниже добавляют исключения.
forbid (principal, Action::"connect", resource)
when { true };

// ------------------------------ БАЗОВЫЕ РАЗРЕШЕНИЯ ----------------------------

// Break‑glass (ограниченный): разрешаем любые действия только при действующей сессии.
// Гео‑блок и другие forbid остаются в силе.
permit (principal in Group::"break_glass", action, resource)
when { context.breakglass.valid == true };

// Общие условия для «корпоративных» пользователей с достаточным AAL и приемлемым риском.
permit (principal in Group::"employees", action in {Action::"read", Action::"list"}, resource)
when {
  context.authn.aal >= 2
  && context.risk.score <= 39
  && context.zone in {"corp_lan","vendor_vpn"}
  && context.tls.client_auth == true
};

// ------------------------------ PAYMENTS API ----------------------------------

// Доступ к Payments API для сотрудников/финансов при управляемых устройствах и MFA.
permit (principal in Group::"employees", action in {Action::"read"}, resource)
when {
  resource.app == "payments_api"
  && context.device.profile in {"managed_win11","managed_mac"}
  && context.authn.aal >= 2
  && ("webauthn" in context.authn.mfa_methods || "totp" in context.authn.mfa_methods || "push" in context.authn.mfa_methods)
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// Финансовые пользователи: разрешаем операции закрытия периода при наличии утверждения.
permit (principal in Group::"finance", action in {Action::"write"}, resource)
when {
  resource.app == "payments_api"
  && "finance_month_end_stepup" in context.approval.ids
  && "pci" in resource.labels
  && context.device.profile in {"managed_win11","managed_mac"}
  && context.authn.aal >= 2
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// Админ‑пути Payments: только админам и только с WebAuthn (AAL3).
permit (principal in Group::"payments_admins", action in {Action::"admin", Action::"write", Action::"delete"}, resource)
when {
  resource.app == "payments_api"
  && "admin" in resource.labels
  && context.authn.aal >= 3
  && "webauthn" in context.authn.mfa_methods
  && context.device.profile in {"managed_win11","managed_mac"}
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// ------------------------------ HR ПОРТАЛ -------------------------------------

// Чтение HR портала для сотрудников и подрядчиков.
permit (principal in Group::"employees", action in {Action::"read","Action::list"}, resource)
when { resource.app == "hr_portal" };

permit (principal in Group::"contractors", action in {Action::"read"}, resource)
when { resource.app == "hr_portal" };

// Админ HR: только HR‑админам, высокий AAL.
permit (principal in Group::"hr_admin", action in {Action::"admin", Action::"write"}, resource)
when {
  resource.app == "hr_portal"
  && context.authn.aal >= 2
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// ------------------------------ GIT FORGE -------------------------------------

// Чтение репозиториев всем сотрудникам при приемлемом риске.
permit (principal in Group::"employees", action in {Action::"read","Action::list"}, resource)
when {
  resource.app == "git_forge"
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// Push/изменения — только при AAL2+ и управляемом устройстве с EDR.
permit (principal in Group::"employees", action in {Action::"write"}, resource)
when {
  resource.app == "git_forge"
  && context.device.profile in {"managed_win11","managed_mac"}
  && context.device.edr_healthy == true
  && context.authn.aal >= 2
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// Администрирование Git — только группе DevTools‑Admins при AAL3.
permit (principal in Group::"devtools_admins", action in {Action::"admin"}, resource)
when {
  resource.app == "git_forge"
  && context.authn.aal >= 3
  && "webauthn" in context.authn.mfa_methods
  && context.risk.score <= 39
  && context.tls.client_auth == true
};

// ------------------------------ EGRESS КОНТРОЛЬ -------------------------------

// Разрешаем исходящие соединения (Action::"connect") к корпоративным доменам.
permit (principal, Action::"connect", resource)
when {
  resource.dst.category == "corporate"
  && resource.dst.domain.ends_with(".yourorg.example")
  && resource.dst.port == 443
};

// Разрешаем Payments‑сервисам исходящие к провайдерам платежей.
permit (principal in Group::"payments_runtimes", Action::"connect", resource)
when {
  resource.dst.category == "payments"
  && resource.dst.domain in {"api.stripe.com","api.braintreegateway.com"}
  && resource.dst.port == 443
};

// ------------------------------ СЕГМЕНТАЦИЯ ПО ЗОНАМ --------------------------

// Сервис‑к‑сервису разрешено только из доверенных зон.
permit (principal in Group::"workloads", action, resource)
when {
  context.zone in {"corp_lan","vendor_vpn"}
  && context.tls.client_auth == true
  && context.risk.score <= 39
};

// ------------------------------ ПРОЧИЕ БЕЗОПАСНЫЕ ЧТЕНИЯ ----------------------

// Безопасные GET к общим справочникам.
permit (principal, Action::"read", resource)
when {
  resource.app in {"hr_portal","git_forge"}
  && "internal" in resource.labels
  && context.risk.score <= 39
};

// ------------------------------ ЯВНЫЙ ЗАПРЕТ ПО УМОЛЧАНИЮ ---------------------

forbid (principal, action, resource)
when { true };
