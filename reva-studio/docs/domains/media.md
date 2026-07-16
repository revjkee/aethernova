# Media Domain

## Status
Proposed

## Document purpose
This document defines the target production-grade domain model, responsibilities, constraints, security rules, and integration boundaries for the `media` domain in `reva-studio`.

This file is intentionally split into:
- confirmed architectural and security practices derived from official guidance;
- project-specific policies marked as `TBD` where business confirmation is still required.

## Normative basis
The design of this domain should follow these external references:

- OWASP File Upload Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- FastAPI UploadFile reference  
  https://fastapi.tiangolo.com/reference/uploadfile/
- FastAPI request files tutorial  
  https://fastapi.tiangolo.com/tutorial/request-files/
- RFC 9110 HTTP Semantics  
  https://www.rfc-editor.org/rfc/rfc9110.html
- Amazon S3 object model overview  
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingObjects.html

---

## 1. Domain mission

The `media` domain is responsible for secure ingestion, validation, storage, retrieval, lifecycle management, and controlled exposure of user-facing and staff-facing media assets.

In `reva-studio`, this domain exists to support scenarios such as:
- user avatars
- staff avatars
- service gallery images
- before/after content
- portfolio assets
- marketing banners
- rich media attached to notifications or campaigns
- internal documents or protected operational files, if explicitly approved

The domain must ensure:
- safe file intake
- stable addressing
- metadata integrity
- controlled visibility
- extensible processing pipeline
- auditability for security-sensitive actions

---

## 2. Scope

## In scope
- accepting media upload requests
- validating uploaded files
- generating internal media records
- storing original files and derived variants
- attaching media to domain entities through references
- controlling access level and lifecycle status
- exposing download or public-access URLs through application policies
- tracking processing status
- soft delete and retention workflows
- audit-relevant logging for media operations

## Out of scope
- rich content editing UI
- CDN vendor-specific setup
- AI image enhancement logic
- generic document management outside approved media use cases
- legal retention policy final values unless approved by business and compliance owners

---

## 3. Architectural position

The `media` domain should be implemented as an isolated bounded context or strongly separated domain module.

It should not be treated as:
- a random utility folder
- raw file-system glue code
- direct controller-to-storage integration without domain rules

The domain should expose stable application use cases and keep storage/provider details behind infrastructure adapters.

Recommended high-level layering:

- domain
  - entities
  - value objects
  - domain services
  - policies
  - events
- application
  - commands
  - queries
  - DTOs
  - orchestrators
- infrastructure
  - object storage adapter
  - antivirus/scanner adapter
  - image processing adapter
  - URL signer
  - repositories
- presentation
  - API endpoints
  - admin endpoints
  - serializer/view models

---

## 4. Ubiquitous language

Use the following terms consistently across code, docs, logs, and API contracts.

### MediaAsset
The canonical domain record for one uploaded asset.

### Original
The original accepted binary payload after validation and safe persistence.

### Variant
A derived representation of the original, for example thumbnail, preview, optimized web image, or cropped version.

### Owner
The domain entity or actor that logically owns or is associated with the media asset.

### Attachment
A link between `MediaAsset` and another domain object such as `User`, `StaffProfile`, `Service`, `Booking`, or `Campaign`.

### Visibility
The access model of the asset:
- private
- protected
- public

### Processing
Asynchronous or synchronous transformation steps applied after upload.

### Quarantine
A temporary restricted state for files pending malware or policy validation.

### Retention
Rules controlling archival or deletion timing.

### Signed URL
A time-limited URL issued by the application or storage gateway for controlled access.

---

## 5. Core domain goals

The `media` domain must optimize for the following goals, in this order:

1. Security
2. Integrity
3. Traceability
4. Operational simplicity
5. Scalability
6. Developer ergonomics

This order is intentional. Unrestricted or weakly validated file upload is a known security risk and must not be treated as a minor implementation detail.

---

## 6. Business capabilities

The domain should support these business capabilities.

### 6.1 Upload asset
Accept a file together with domain context and policy hints.

### 6.2 Validate asset
Validate extension, content type, binary signature where applicable, file size, and authorization.

### 6.3 Persist asset
Store the original payload and persist metadata in the application database.

### 6.4 Process asset
Create safe and policy-approved derivatives such as thumbnails or optimized previews.

### 6.5 Attach asset
Associate the asset with a business entity through typed references.

### 6.6 Serve asset
Provide public URL, protected URL, or signed URL according to visibility policy.

### 6.7 Replace asset
Replace the currently active asset while preserving auditability and historical references if required.

### 6.8 Retire asset
Soft delete, archive, or hard delete according to retention policy.

---

## 7. Proposed domain model

## 7.1 Entity: MediaAsset

`MediaAsset` is the aggregate root.

### Suggested fields
- `id: UUID`
- `storage_key: str`
- `bucket_name: str | None`
- `original_filename: str`
- `sanitized_filename: str`
- `media_type: str`
- `detected_content_type: str | None`
- `extension: str | None`
- `size_bytes: int`
- `checksum_sha256: str`
- `width: int | None`
- `height: int | None`
- `duration_ms: int | None`
- `visibility: MediaVisibility`
- `status: MediaStatus`
- `processing_status: ProcessingStatus`
- `owner_type: str | None`
- `owner_id: UUID | str | None`
- `created_by_user_id: UUID | None`
- `created_at: datetime`
- `updated_at: datetime`
- `deleted_at: datetime | None`
- `quarantined_at: datetime | None`
- `scan_status: ScanStatus`
- `retention_policy_code: str | None`
- `metadata_json: dict[str, Any]`

### Responsibilities
- enforce invariant correctness
- prevent illegal state transitions
- expose domain methods for visibility and lifecycle changes
- remain storage-provider agnostic

## 7.2 Value object: MediaVisibility
Allowed values:
- `private`
- `protected`
- `public`

## 7.3 Value object: MediaStatus
Suggested values:
- `uploaded`
- `validated`
- `stored`
- `active`
- `replaced`
- `quarantined`
- `deleted`
- `archived`
- `failed`

## 7.4 Value object: ProcessingStatus
Suggested values:
- `pending`
- `running`
- `completed`
- `partially_completed`
- `failed`
- `skipped`

## 7.5 Value object: ScanStatus
Suggested values:
- `pending`
- `clean`
- `infected`
- `unsupported`
- `failed`

## 7.6 Entity: MediaVariant
Represents a derived file belonging to a `MediaAsset`.

### Suggested fields
- `id: UUID`
- `media_asset_id: UUID`
- `variant_type: str`
- `storage_key: str`
- `content_type: str`
- `size_bytes: int`
- `width: int | None`
- `height: int | None`
- `checksum_sha256: str`
- `created_at: datetime`

### Example `variant_type`
- `thumbnail_sm`
- `thumbnail_md`
- `preview_webp`
- `admin_preview`
- `hero_banner`
- `original_normalized`

## 7.7 Entity: MediaAttachment
If one asset may be attached to multiple business entities, model the relation explicitly.

### Suggested fields
- `id: UUID`
- `media_asset_id: UUID`
- `target_type: str`
- `target_id: UUID | str`
- `role: str`
- `sort_order: int`
- `is_primary: bool`
- `created_at: datetime`

### Example `role`
- `avatar`
- `cover`
- `gallery`
- `before`
- `after`
- `receipt`
- `document`

---

## 8. Aggregate invariants

The following invariants should hold.

1. A media asset must have a stable internal identifier.
2. A stored asset must have a storage key.
3. A stored asset must have a non-zero byte size.
4. A media asset must have a calculated checksum before becoming `active`.
5. A quarantined or infected asset must not be publicly exposed.
6. A deleted asset must not accept new attachments.
7. A public asset must pass all validation and policy checks before public exposure.
8. A variant cannot exist without a parent `MediaAsset`.
9. `original_filename` is preserved for audit and UX, but storage naming must not trust client-provided names.
10. Visibility changes must be explicit domain operations, not ad hoc field edits.

---

## 9. Security requirements

This section is mandatory and non-optional for implementation.

## 9.1 Validation strategy
The upload pipeline must use defense in depth.

Minimum controls:
- allowlist file extensions
- allowlist business-approved media types
- verify actual content where feasible
- validate file signature or magic bytes where feasible
- rename files on persistence
- enforce file size limits
- reject dangerous active content when not explicitly allowed
- store files outside direct webroot when self-hosted
- perform authorization checks before upload and before retrieval
- support malware scanning or quarantine flow where required

## 9.2 Dangerous patterns to forbid
Unless explicitly approved by security review, reject:
- executable files
- script-like files
- HTML uploads for direct rendering
- SVG with active or unsanitized content in public contexts
- office files in image-only flows
- polyglot files where validation is inconclusive

## 9.3 Public exposure rule
No file becomes publicly accessible merely because it was uploaded.
Public exposure requires:
- successful validation
- clean or approved scan status
- valid storage state
- explicit visibility policy
- explicit attach/use-case approval

## 9.4 Authorization rule
The actor allowed to upload, replace, read, or delete media must be checked against:
- tenant boundary
- role/permission
- ownership or scoped access
- target entity rules

## 9.5 Metadata trust rule
Client-provided metadata is not authoritative.
The server should independently determine or verify:
- content type
- byte size
- checksum
- image dimensions where applicable

---

## 10. Storage model

A provider-neutral object storage model is recommended.

## 10.1 Rationale
Object storage maps naturally to media assets because the storage unit is an object containing file payload and metadata.

## 10.2 Recommended storage abstraction
The application should depend on an interface similar to:

- `put_object`
- `get_object`
- `delete_object`
- `head_object`
- `generate_signed_url`
- `copy_object`
- `set_object_tags`
- `get_object_metadata`

## 10.3 Storage key design
Storage keys should be deterministic enough for operability and random enough to avoid collisions and enumeration.

Recommended pattern:
`{environment}/{tenant_id}/{asset_kind}/{yyyy}/{mm}/{uuid}-{normalized-suffix}`

Example:
`prod/tenant_42/staff-avatar/2026/03/8d7b9f5a-preview.webp`

Do not use raw client filename as the storage key.

## 10.4 Bucket strategy
Bucket layout is project-specific and must be finalized by infrastructure owners.

Suggested options:
- one bucket per environment
- one bucket per sensitivity class
- one bucket per deployment boundary

`TBD`:
- exact bucket naming convention
- cross-region policy
- encryption-at-rest provider settings
- lifecycle archival tiers

---

## 11. Access model

## 11.1 Private
Accessible only through authenticated application-controlled requests.

Use for:
- internal files
- receipts
- operational documents
- moderation-only assets

## 11.2 Protected
Accessible via signed URLs or gateway-checked endpoints.

Use for:
- staff-only previews
- customer-specific files
- expiring downloadable artifacts

## 11.3 Public
Accessible through public URL or CDN after explicit approval.

Use for:
- service gallery images
- public banners
- marketing assets
- approved portfolio content

---

## 12. Upload pipeline

Recommended target flow:

1. authenticate actor
2. authorize upload target and role
3. receive file through streaming-safe API
4. validate declared and detected type
5. enforce size and policy constraints
6. calculate checksum
7. optionally store in quarantine location
8. run scan or enqueue scan
9. persist `MediaAsset`
10. promote to active storage if clean
11. emit domain event
12. trigger derivative generation if configured

### Important note
The exact sync vs async split is deployment-specific.
If malware scanning or image processing is asynchronous, the initial asset should remain non-public until the required checks complete.

---

## 13. Retrieval pipeline

Recommended read flow:

1. authenticate request if asset is not public
2. authorize against tenant and owner scope
3. load `MediaAsset`
4. verify lifecycle state
5. resolve original or variant
6. issue stream or signed URL
7. record audit/security log where required

---

## 14. Lifecycle states

Suggested lifecycle:

`uploaded -> validated -> stored -> active`

Exceptional branches:
- `uploaded -> quarantined`
- `uploaded -> failed`
- `active -> replaced`
- `active -> archived`
- `active -> deleted`

State transitions should be implemented as explicit methods or policy-guarded application commands.

---

## 15. Recommended commands

Suggested application commands:

- `UploadMediaCommand`
- `ValidateMediaCommand`
- `AttachMediaCommand`
- `ReplaceMediaCommand`
- `GenerateMediaVariantCommand`
- `PublishMediaCommand`
- `UnpublishMediaCommand`
- `DeleteMediaCommand`
- `RestoreMediaCommand`
- `ScanMediaCommand`

---

## 16. Recommended queries

Suggested application queries:

- `GetMediaAssetByIdQuery`
- `GetMediaByOwnerQuery`
- `GetMediaVariantsQuery`
- `GetPublicMediaUrlQuery`
- `GetProtectedMediaUrlQuery`
- `SearchMediaAssetsQuery`

---

## 17. Domain events

Suggested events:

- `MediaUploaded`
- `MediaValidated`
- `MediaQuarantined`
- `MediaScanCompleted`
- `MediaActivated`
- `MediaVariantGenerated`
- `MediaAttached`
- `MediaPublished`
- `MediaDeleted`
- `MediaRestored`

These events are useful for:
- audit trail
- cache invalidation
- CDN purge hooks
- async processing
- search indexing
- analytics

---

## 18. Business policies

## 18.1 File size policy
Final limits must be approved per media role.

`TBD`:
- avatar max size
- gallery image max size
- banner max size
- document max size
- video max size

## 18.2 Allowed format policy
Final formats must be approved by product and security owners.

Suggested initial posture:
- images: JPEG, PNG, WEBP
- documents: only if explicitly required by a business use case
- video: only after confirming storage, transcoding, and moderation policy

Do not enable additional formats by default.

## 18.3 Retention policy
Final retention values must be approved.

`TBD`:
- deleted assets retention days
- quarantine retention days
- unattached assets cleanup policy
- legal hold policy
- backup retention relation

---

## 19. Multi-tenant requirements

If `reva-studio` is multi-tenant, the media domain must enforce tenant isolation in:
- metadata queries
- storage key strategy
- signed URL issuance
- background processing
- admin moderation views
- deletion jobs
- logs and metrics labels

A tenant must never receive access to another tenant's protected media through ID guessing, shared bucket misconfiguration, or weak authorization checks.

---

## 20. Observability requirements

The media domain should expose the following operational signals.

## 20.1 Logs
Structured logs should include:
- request_id
- actor_id
- tenant_id
- media_asset_id
- target_type
- target_id
- content_type_detected
- size_bytes
- scan_status
- result
- failure_reason_code

Do not log secrets, signed URLs, raw tokens, or full sensitive metadata.

## 20.2 Metrics
Recommended metrics:
- upload_requests_total
- upload_rejections_total
- upload_bytes_total
- media_processing_duration_seconds
- scan_failures_total
- active_assets_total
- signed_url_issuance_total
- media_delete_total

## 20.3 Tracing
Recommended spans:
- upload.receive
- upload.validate
- upload.store
- upload.scan
- media.variant.generate
- media.url.sign

---

## 21. API design guidance

This document does not freeze the final REST schema, but the following principles should apply.

### Upload endpoint principles
- multipart handling should use framework-supported file upload primitives
- metadata should be explicit and validated
- response should return canonical asset identifier and current state
- asynchronous processing should be reflected in the returned status

### Retrieval endpoint principles
- do not expose raw storage provider details unless intended
- do not return permanent protected URLs
- prefer short-lived signed URLs or streamed gateway responses for non-public content

### Delete endpoint principles
- default to soft delete unless hard delete is explicitly required
- record who initiated deletion
- ensure attachment integrity rules are enforced

---

## 22. Database design guidance

Suggested table set:

### `media_assets`
Primary metadata table.

### `media_variants`
One-to-many from assets.

### `media_attachments`
Typed relation to business entities.

### `media_audit_log`
Optional dedicated audit table for sensitive operations.

### `media_processing_jobs`
Optional if processing is orchestrated internally.

Indexes to consider:
- by `owner_type`, `owner_id`
- by `created_at`
- by `visibility`
- by `status`
- by `checksum_sha256`
- by `tenant_id` if applicable

Unique constraints should be conservative and business-driven.

---

## 23. Failure handling

The domain should explicitly handle:
- unsupported format
- file too large
- content-type mismatch
- checksum failure
- storage write failure
- scan timeout
- processing timeout
- unauthorized access
- orphaned metadata
- orphaned object in storage
- duplicate upload with same checksum policy

A failed media operation should produce a consistent state that can be retried or cleaned up.

---

## 24. Idempotency guidance

For upload-heavy systems, idempotency should be considered for:
- client retries
- network failures
- duplicate submit actions
- worker retries

Possible strategies:
- request idempotency key
- checksum-based duplicate detection
- storage key reservation
- exactly-once event publishing where feasible

Final project policy is `TBD`.

---

## 25. Data privacy considerations

This domain may process user-generated content and staff media.
Therefore:
- privacy classification must be defined
- access logs may be required for protected assets
- moderation or review workflows may be needed for public publication
- personal data handling rules must align with the wider platform compliance model

Final classification matrix is `TBD`.

---

## 26. Recommended integration boundaries

The `media` domain may integrate with:
- `users`
- `staff`
- `services_catalog`
- `bookings`
- `marketing`
- `notifications`
- `admin`
- `audit`
- `observability`

The domain should not leak raw storage SDK objects into those modules.

---

## 27. Suggested Python code structure

```text
src/reva_studio/media/
├── domain/
│   ├── entities/
│   │   ├── media_asset.py
│   │   ├── media_variant.py
│   │   └── media_attachment.py
│   ├── value_objects/
│   │   ├── media_visibility.py
│   │   ├── media_status.py
│   │   ├── processing_status.py
│   │   └── scan_status.py
│   ├── events/
│   │   └── media_events.py
│   ├── policies/
│   │   ├── media_validation_policy.py
│   │   ├── media_visibility_policy.py
│   │   └── media_retention_policy.py
│   └── services/
│       └── media_domain_service.py
├── application/
│   ├── commands/
│   ├── queries/
│   ├── dto/
│   └── handlers/
├── infrastructure/
│   ├── storage/
│   ├── scanning/
│   ├── imaging/
│   ├── signing/
│   └── repositories/
└── presentation/
    ├── api/
    └── admin/