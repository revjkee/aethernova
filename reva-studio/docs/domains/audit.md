openapi: 3.1.0
info:
  title: Reva Studio Public API
  version: 1.0.0
  summary: Public client-facing API for booking, catalog, profile and loyalty workflows.
  description: |
    Public API of Reva Studio for client applications, Telegram Mini App integrations,
    mobile/web frontends and partner-safe public workflows.

    Scope of this specification:
      - public health and metadata endpoints
      - public service catalog
      - public specialists and availability
      - client self-service profile endpoints
      - booking lifecycle for authenticated clients
      - loyalty balance and history for authenticated clients

    Out of scope:
      - internal administration
      - backoffice management
      - privileged analytics
      - internal operational endpoints
      - infrastructure-only endpoints

    Design principles:
      - stable external contract
      - predictable error handling
      - idempotent booking creation
      - pagination-ready collections
      - tenant-aware routing
      - timezone-explicit date and time handling

jsonSchemaDialect: https://json-schema.org/draft/2020-12/schema

servers:
  - url: https://api.revastudio.example.com/public/v1
    description: Production
  - url: https://staging-api.revastudio.example.com/public/v1
    description: Staging
  - url: http://localhost:8000/public/v1
    description: Local development

security:
  - bearerAuth: []

tags:
  - name: Meta
    description: Public metadata and service health.
  - name: Catalog
    description: Public catalog of services and categories.
  - name: Specialists
    description: Public specialist directory and related availability.
  - name: Availability
    description: Read-only public slot availability.
  - name: Auth
    description: Public authentication and session lifecycle.
  - name: Clients
    description: Authenticated client self-service profile operations.
  - name: Bookings
    description: Authenticated client booking lifecycle.
  - name: Loyalty
    description: Authenticated client loyalty balance and transactions.

paths:
  /health:
    get:
      tags: [Meta]
      summary: Public health check
      description: Returns minimal public health information for API consumers.
      security: []
      operationId: getPublicHealth
      responses:
        '200':
          description: Public API is healthy.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PublicHealthResponse'
              examples:
                default:
                  value:
                    status: ok
                    service: reva-studio-public-api
                    version: 1.0.0
                    environment: production
                    time: '2026-03-23T10:15:00Z'

  /meta:
    get:
      tags: [Meta]
      summary: Get public API metadata
      description: Returns metadata useful for public clients.
      security: []
      operationId: getPublicMeta
      responses:
        '200':
          description: Public metadata.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PublicMetaResponse'

  /auth/guest:
    post:
      tags: [Auth]
      summary: Create guest session
      description: |
        Creates a guest session for anonymous browsing flows.
        Guest sessions cannot access authenticated profile, loyalty or booking history endpoints.
      security: []
      operationId: createGuestSession
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/GuestSessionCreateRequest'
      responses:
        '201':
          description: Guest session created.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthSessionResponse'
        '400':
          $ref: '#/components/responses/BadRequest'

  /auth/login:
    post:
      tags: [Auth]
      summary: Sign in client
      description: Authenticates a client and returns access and refresh tokens.
      security: []
      operationId: loginClient
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Client authenticated.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthSessionResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'

  /auth/refresh:
    post:
      tags: [Auth]
      summary: Refresh access token
      description: Exchanges a refresh token for a new token pair.
      security: []
      operationId: refreshSession
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenRefreshRequest'
      responses:
        '200':
          description: Session refreshed.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthSessionResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'

  /auth/logout:
    post:
      tags: [Auth]
      summary: Sign out current session
      description: Invalidates the current refresh token or session family depending on implementation.
      operationId: logoutSession
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LogoutRequest'
      responses:
        '204':
          description: Session invalidated.
        '401':
          $ref: '#/components/responses/Unauthorized'

  /catalog/categories:
    get:
      tags: [Catalog]
      summary: List service categories
      description: Returns public service categories available for the selected tenant.
      security: []
      operationId: listServiceCategories
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - $ref: '#/components/parameters/LocaleHeader'
      responses:
        '200':
          description: List of service categories.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ServiceCategoryListResponse'

  /catalog/services:
    get:
      tags: [Catalog]
      summary: List services
      description: Returns public service catalog items.
      security: []
      operationId: listServices
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - $ref: '#/components/parameters/LocaleHeader'
        - name: category_id
          in: query
          description: Filter by category identifier.
          required: false
          schema:
            $ref: '#/components/schemas/Id'
        - name: specialist_id
          in: query
          description: Filter services available for a given specialist.
          required: false
          schema:
            $ref: '#/components/schemas/Id'
        - name: is_active
          in: query
          description: Filter active services only.
          required: false
          schema:
            type: boolean
            default: true
        - $ref: '#/components/parameters/LimitQuery'
        - $ref: '#/components/parameters/OffsetQuery'
      responses:
        '200':
          description: List of services.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ServiceListResponse'

  /catalog/services/{service_id}:
    get:
      tags: [Catalog]
      summary: Get service details
      description: Returns public details of a service.
      security: []
      operationId: getService
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: service_id
          in: path
          required: true
          schema:
            $ref: '#/components/schemas/Id'
      responses:
        '200':
          description: Service details.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ServiceResponse'
        '404':
          $ref: '#/components/responses/NotFound'

  /specialists:
    get:
      tags: [Specialists]
      summary: List specialists
      description: Returns public specialist cards for booking flows.
      security: []
      operationId: listSpecialists
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - $ref: '#/components/parameters/LocaleHeader'
        - name: service_id
          in: query
          description: Filter specialists who can provide the service.
          required: false
          schema:
            $ref: '#/components/schemas/Id'
        - name: is_active
          in: query
          required: false
          schema:
            type: boolean
            default: true
        - $ref: '#/components/parameters/LimitQuery'
        - $ref: '#/components/parameters/OffsetQuery'
      responses:
        '200':
          description: List of specialists.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SpecialistListResponse'

  /specialists/{specialist_id}:
    get:
      tags: [Specialists]
      summary: Get specialist details
      description: Returns public specialist details.
      security: []
      operationId: getSpecialist
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: specialist_id
          in: path
          required: true
          schema:
            $ref: '#/components/schemas/Id'
      responses:
        '200':
          description: Specialist details.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SpecialistResponse'
        '404':
          $ref: '#/components/responses/NotFound'

  /availability/slots:
    get:
      tags: [Availability]
      summary: Search available slots
      description: |
        Returns public available booking slots.
        Time values are returned in the tenant timezone and also as UTC timestamps.
      security: []
      operationId: searchAvailableSlots
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: service_id
          in: query
          required: true
          schema:
            $ref: '#/components/schemas/Id'
        - name: specialist_id
          in: query
          required: false
          schema:
            $ref: '#/components/schemas/Id'
        - name: from_date
          in: query
          required: true
          schema:
            type: string
            format: date
        - name: to_date
          in: query
          required: true
          schema:
            type: string
            format: date
        - name: timezone
          in: query
          description: Preferred IANA timezone for display.
          required: false
          schema:
            type: string
            example: Europe/Riga
        - $ref: '#/components/parameters/LimitQuery'
      responses:
        '200':
          description: Available slots.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AvailabilitySlotListResponse'
        '400':
          $ref: '#/components/responses/BadRequest'

  /clients/me:
    get:
      tags: [Clients]
      summary: Get current client profile
      description: Returns the authenticated client profile.
      operationId: getCurrentClient
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
      responses:
        '200':
          description: Current client profile.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ClientProfileResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'
    patch:
      tags: [Clients]
      summary: Update current client profile
      description: Updates editable fields of the authenticated client profile.
      operationId: updateCurrentClient
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ClientProfileUpdateRequest'
      responses:
        '200':
          description: Updated client profile.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ClientProfileResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'

  /clients/me/bookings:
    get:
      tags: [Bookings]
      summary: List current client bookings
      description: Returns bookings of the authenticated client.
      operationId: listCurrentClientBookings
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: status
          in: query
          required: false
          schema:
            $ref: '#/components/schemas/BookingStatus'
        - name: upcoming_only
          in: query
          required: false
          schema:
            type: boolean
            default: false
        - $ref: '#/components/parameters/LimitQuery'
        - $ref: '#/components/parameters/OffsetQuery'
      responses:
        '200':
          description: Client bookings.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BookingListResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'

  /bookings:
    post:
      tags: [Bookings]
      summary: Create booking
      description: |
        Creates a booking for the authenticated client.

        Idempotency:
          Clients should send the `Idempotency-Key` header for safe retries.
      operationId: createBooking
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - $ref: '#/components/parameters/IdempotencyKeyHeader'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BookingCreateRequest'
      responses:
        '201':
          description: Booking created.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BookingResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '409':
          $ref: '#/components/responses/Conflict'
        '422':
          $ref: '#/components/responses/UnprocessableEntity'

  /bookings/{booking_id}:
    get:
      tags: [Bookings]
      summary: Get booking
      description: Returns a booking belonging to the authenticated client.
      operationId: getBooking
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: booking_id
          in: path
          required: true
          schema:
            $ref: '#/components/schemas/Id'
      responses:
        '200':
          description: Booking details.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BookingResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '404':
          $ref: '#/components/responses/NotFound'

  /bookings/{booking_id}/cancel:
    post:
      tags: [Bookings]
      summary: Cancel booking
      description: Cancels a client booking if cancellation rules allow it.
      operationId: cancelBooking
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: booking_id
          in: path
          required: true
          schema:
            $ref: '#/components/schemas/Id'
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BookingCancelRequest'
      responses:
        '200':
          description: Booking cancelled.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BookingResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '404':
          $ref: '#/components/responses/NotFound'
        '409':
          $ref: '#/components/responses/Conflict'

  /bookings/{booking_id}/reschedule:
    post:
      tags: [Bookings]
      summary: Reschedule booking
      description: Changes a booking to another available slot.
      operationId: rescheduleBooking
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: booking_id
          in: path
          required: true
          schema:
            $ref: '#/components/schemas/Id'
        - $ref: '#/components/parameters/IdempotencyKeyHeader'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BookingRescheduleRequest'
      responses:
        '200':
          description: Booking rescheduled.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BookingResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '404':
          $ref: '#/components/responses/NotFound'
        '409':
          $ref: '#/components/responses/Conflict'
        '422':
          $ref: '#/components/responses/UnprocessableEntity'

  /loyalty/me:
    get:
      tags: [Loyalty]
      summary: Get loyalty account
      description: Returns loyalty summary for the authenticated client.
      operationId: getCurrentLoyaltyAccount
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
      responses:
        '200':
          description: Loyalty account summary.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoyaltyAccountResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'

  /loyalty/me/transactions:
    get:
      tags: [Loyalty]
      summary: List loyalty transactions
      description: Returns loyalty accrual and redemption history of the authenticated client.
      operationId: listCurrentLoyaltyTransactions
      parameters:
        - $ref: '#/components/parameters/TenantIdHeader'
        - name: type
          in: query
          required: false
          schema:
            $ref: '#/components/schemas/LoyaltyTransactionType'
        - $ref: '#/components/parameters/LimitQuery'
        - $ref: '#/components/parameters/OffsetQuery'
      responses:
        '200':
          description: Loyalty transaction history.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoyaltyTransactionListResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'

components:
  parameters:
    TenantIdHeader:
      name: X-Tenant-Id
      in: header
      required: true
      description: Public tenant identifier.
      schema:
        type: string
        minLength: 1
        maxLength: 64
        example: rvstd-main
    LocaleHeader:
      name: Accept-Language
      in: header
      required: false
      description: Preferred locale for localized text fields.
      schema:
        type: string
        example: ru-RU
    IdempotencyKeyHeader:
      name: Idempotency-Key
      in: header
      required: false
      description: Unique key used for safe request retries.
      schema:
        type: string
        minLength: 8
        maxLength: 128
        example: 8f8f4e2f-7d63-4f71-a9d0-c2bcb3cb7f4b
    LimitQuery:
      name: limit
      in: query
      required: false
      description: Maximum number of returned items.
      schema:
        type: integer
        minimum: 1
        maximum: 100
        default: 20
    OffsetQuery:
      name: offset
      in: query
      required: false
      description: Collection offset.
      schema:
        type: integer
        minimum: 0
        default: 0

  responses:
    BadRequest:
      description: Request validation failed.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          examples:
            default:
              value:
                error:
                  code: bad_request
                  message: Request validation failed.
                  request_id: 6f4cd09032f44543b3c2622f7f6991d9
                  details:
                    - field: phone
                      reason: invalid_format
    Unauthorized:
      description: Authentication failed or missing.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          examples:
            default:
              value:
                error:
                  code: unauthorized
                  message: Authentication is required.
                  request_id: e8d04e9e423d4aa59255b6e3de2a2536
    NotFound:
      description: Resource not found.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          examples:
            default:
              value:
                error:
                  code: not_found
                  message: Requested resource was not found.
                  request_id: 7153caef6c0945ac94c6147dc31a661c
    Conflict:
      description: Resource conflict or booking rule conflict.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          examples:
            slot_taken:
              value:
                error:
                  code: booking_conflict
                  message: The selected slot is no longer available.
                  request_id: 3c8fcad6920449f3a2f40c0f7e2a2b13
    UnprocessableEntity:
      description: Business rule violation.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          examples:
            cancellation_window:
              value:
                error:
                  code: booking_policy_violation
                  message: Cancellation is not allowed within the configured policy window.
                  request_id: 13063f676d944113a719f7d2afc03c9d

  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    Id:
      type: string
      minLength: 1
      maxLength: 64
      pattern: '^[A-Za-z0-9._:-]+$'
      example: svc_manicure_classic

    ISODateTime:
      type: string
      format: date-time
      example: '2026-03-23T10:30:00Z'

    Money:
      type: object
      additionalProperties: false
      required: [amount, currency]
      properties:
        amount:
          type: string
          description: Decimal amount as string to avoid floating point ambiguity.
          pattern: '^-?\d+(\.\d{1,2})?$'
          example: '2500.00'
        currency:
          type: string
          minLength: 3
          maxLength: 3
          example: RUB

    Pagination:
      type: object
      additionalProperties: false
      required: [limit, offset, total]
      properties:
        limit:
          type: integer
          minimum: 1
          example: 20
        offset:
          type: integer
          minimum: 0
          example: 0
        total:
          type: integer
          minimum: 0
          example: 125

    PublicHealthResponse:
      type: object
      additionalProperties: false
      required: [status, service, version, environment, time]
      properties:
        status:
          type: string
          enum: [ok]
        service:
          type: string
          example: reva-studio-public-api
        version:
          type: string
          example: 1.0.0
        environment:
          type: string
          example: production
        time:
          $ref: '#/components/schemas/ISODateTime'

    PublicMetaResponse:
      type: object
      additionalProperties: false
      required:
        - api_name
        - api_version
        - tenant_required
        - auth_methods
        - timezone_default
      properties:
        api_name:
          type: string
          example: Reva Studio Public API
        api_version:
          type: string
          example: 1.0.0
        tenant_required:
          type: boolean
          example: true
        auth_methods:
          type: array
          items:
            type: string
            enum: [guest, bearer]
          example: [guest, bearer]
        timezone_default:
          type: string
          example: Europe/Riga

    GuestSessionCreateRequest:
      type: object
      additionalProperties: false
      properties:
        device_id:
          type: string
          maxLength: 128
        locale:
          type: string
          maxLength: 16
          example: ru-RU

    LoginRequest:
      type: object
      additionalProperties: false
      required: [phone, otp_code]
      properties:
        phone:
          type: string
          minLength: 5
          maxLength: 32
          example: '+79990000000'
        otp_code:
          type: string
          minLength: 4
          maxLength: 16
          example: '123456'
        device_id:
          type: string
          maxLength: 128

    TokenRefreshRequest:
      type: object
      additionalProperties: false
      required: [refresh_token]
      properties:
        refresh_token:
          type: string
          minLength: 16

    LogoutRequest:
      type: object
      additionalProperties: false
      properties:
        refresh_token:
          type: string
          minLength: 16
        all_sessions:
          type: boolean
          default: false

    AuthSessionResponse:
      type: object
      additionalProperties: false
      required:
        - access_token
        - refresh_token
        - token_type
        - expires_in
        - subject
        - session_kind
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
        token_type:
          type: string
          enum: [Bearer]
        expires_in:
          type: integer
          minimum: 1
          example: 3600
        subject:
          type: string
          example: client_01HTWQ7RMQ0K4X7VQJ18D4K1W3
        session_kind:
          type: string
          enum: [guest, client]

    LocalizedText:
      type: object
      additionalProperties:
        type: string
      example:
        ru: Маникюр классический
        en: Classic manicure

    ServiceCategory:
      type: object
      additionalProperties: false
      required: [id, code, name, sort_order, is_active]
      properties:
        id:
          $ref: '#/components/schemas/Id'
        code:
          type: string
          maxLength: 64
          example: manicure
        name:
          oneOf:
            - type: string
            - $ref: '#/components/schemas/LocalizedText'
        description:
          oneOf:
            - type: string
            - $ref: '#/components/schemas/LocalizedText'
            - type: 'null'
        sort_order:
          type: integer
          minimum: 0
          example: 10
        is_active:
          type: boolean
          example: true

    ServiceCategoryListResponse:
      type: object
      additionalProperties: false
      required: [items]
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/ServiceCategory'

    Service:
      type: object
      additionalProperties: false
      required:
        - id
        - code
        - category_id
        - name
        - duration_minutes
        - price
        - is_active
      properties:
        id:
          $ref: '#/components/schemas/Id'
        code:
          type: string
          maxLength: 64
          example: classic-manicure
        category_id:
          $ref: '#/components/schemas/Id'
        name:
          oneOf:
            - type: string
            - $ref: '#/components/schemas/LocalizedText'
        description:
          oneOf:
            - type: string
            - $ref: '#/components/schemas/LocalizedText'
            - type: 'null'
        duration_minutes:
          type: integer
          minimum: 5
          maximum: 720
          example: 90
        price:
          $ref: '#/components/schemas/Money'
        is_active:
          type: boolean
          example: true
        requires_confirmation:
          type: boolean
          default: false
        buffer_before_minutes:
          type: integer
          minimum: 0
          example: 0
        buffer_after_minutes:
          type: integer
          minimum: 0
          example: 15

    ServiceResponse:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          $ref: '#/components/schemas/Service'

    ServiceListResponse:
      type: object
      additionalProperties: false
      required: [items, pagination]
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/Service'
        pagination:
          $ref: '#/components/schemas/Pagination'

    Specialist:
      type: object
      additionalProperties: false
      required:
        - id
        - display_name
        - is_active
        - service_ids
      properties:
        id:
          $ref: '#/components/schemas/Id'
        display_name:
          type: string
          maxLength: 128
          example: Анна Петрова
        bio:
          type:
            - string
            - 'null'
          maxLength: 5000
        avatar_url:
          type:
            - string
            - 'null'
          format: uri
        is_active:
          type: boolean
          example: true
        service_ids:
          type: array
          items:
            $ref: '#/components/schemas/Id'
        rating:
          type:
            - number
            - 'null'
          minimum: 0
          maximum: 5
          example: 4.9
        experience_years:
          type:
            - integer
            - 'null'
          minimum: 0
          example: 5

    SpecialistResponse:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          $ref: '#/components/schemas/Specialist'

    SpecialistListResponse:
      type: object
      additionalProperties: false
      required: [items, pagination]
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/Specialist'
        pagination:
          $ref: '#/components/schemas/Pagination'

    AvailabilitySlot:
      type: object
      additionalProperties: false
      required:
        - slot_id
        - service_id
        - specialist_id
        - starts_at
        - ends_at
        - starts_at_local
        - ends_at_local
        - timezone
      properties:
        slot_id:
          type: string
          maxLength: 128
          example: slot_2026-03-25T09:00:00+03:00_spc_anna_service_manicure
        service_id:
          $ref: '#/components/schemas/Id'
        specialist_id:
          $ref: '#/components/schemas/Id'
        starts_at:
          $ref: '#/components/schemas/ISODateTime'
        ends_at:
          $ref: '#/components/schemas/ISODateTime'
        starts_at_local:
          type: string
          example: '2026-03-25T12:00:00+03:00'
        ends_at_local:
          type: string
          example: '2026-03-25T13:30:00+03:00'
        timezone:
          type: string
          example: Europe/Moscow
        specialist_name:
          type:
            - string
            - 'null'
          example: Анна Петрова
        service_name:
          type:
            - string
            - 'null'
          example: Маникюр классический

    AvailabilitySlotListResponse:
      type: object
      additionalProperties: false
      required: [items, pagination]
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/AvailabilitySlot'
        pagination:
          $ref: '#/components/schemas/Pagination'

    ClientProfile:
      type: object
      additionalProperties: false
      required:
        - id
        - phone
        - first_name
        - loyalty_enrolled
        - created_at
      properties:
        id:
          $ref: '#/components/schemas/Id'
        phone:
          type: string
          example: '+79990000000'
        first_name:
          type: string
          maxLength: 128
          example: Влад
        last_name:
          type:
            - string
            - 'null'
          maxLength: 128
        birth_date:
          type:
            - string
            - 'null'
          format: date
        email:
          type:
            - string
            - 'null'
          format: email
        notes_for_staff:
          type:
            - string
            - 'null'
          maxLength: 2000
        loyalty_enrolled:
          type: boolean
          example: true
        created_at:
          $ref: '#/components/schemas/ISODateTime'
        updated_at:
          oneOf:
            - $ref: '#/components/schemas/ISODateTime'
            - type: 'null'

    ClientProfileResponse:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          $ref: '#/components/schemas/ClientProfile'

    ClientProfileUpdateRequest:
      type: object
      additionalProperties: false
      properties:
        first_name:
          type: string
          minLength: 1
          maxLength: 128
        last_name:
          type:
            - string
            - 'null'
          maxLength: 128
        birth_date:
          type:
            - string
            - 'null'
          format: date
        email:
          type:
            - string
            - 'null'
          format: email
        notes_for_staff:
          type:
            - string
            - 'null'
          maxLength: 2000

    BookingStatus:
      type: string
      enum:
        - pending
        - confirmed
        - cancelled
        - completed
        - no_show

    Booking:
      type: object
      additionalProperties: false
      required:
        - id
        - client_id
        - service_id
        - service_name
        - specialist_id
        - specialist_name
        - status
        - starts_at
        - ends_at
        - timezone
        - price
        - created_at
      properties:
        id:
          $ref: '#/components/schemas/Id'
        client_id:
          $ref: '#/components/schemas/Id'
        service_id:
          $ref: '#/components/schemas/Id'
        service_name:
          type: string
          example: Маникюр классический
        specialist_id:
          $ref: '#/components/schemas/Id'
        specialist_name:
          type: string
          example: Анна Петрова
        status:
          $ref: '#/components/schemas/BookingStatus'
        starts_at:
          $ref: '#/components/schemas/ISODateTime'
        ends_at:
          $ref: '#/components/schemas/ISODateTime'
        timezone:
          type: string
          example: Europe/Moscow
        price:
          $ref: '#/components/schemas/Money'
        comment:
          type:
            - string
            - 'null'
          maxLength: 2000
        can_cancel:
          type: boolean
          example: true
        can_reschedule:
          type: boolean
          example: true
        cancellation_reason:
          type:
            - string
            - 'null'
        created_at:
          $ref: '#/components/schemas/ISODateTime'
        updated_at:
          oneOf:
            - $ref: '#/components/schemas/ISODateTime'
            - type: 'null'

    BookingResponse:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          $ref: '#/components/schemas/Booking'

    BookingListResponse:
      type: object
      additionalProperties: false
      required: [items, pagination]
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/Booking'
        pagination:
          $ref: '#/components/schemas/Pagination'

    BookingCreateRequest:
      type: object
      additionalProperties: false
      required:
        - service_id
        - specialist_id
        - starts_at
      properties:
        service_id:
          $ref: '#/components/schemas/Id'
        specialist_id:
          $ref: '#/components/schemas/Id'
        starts_at:
          $ref: '#/components/schemas/ISODateTime'
        comment:
          type: string
          maxLength: 2000

    BookingCancelRequest:
      type: object
      additionalProperties: false
      properties:
        reason:
          type: string
          maxLength: 512

    BookingRescheduleRequest:
      type: object
      additionalProperties: false
      required: [starts_at]
      properties:
        starts_at:
          $ref: '#/components/schemas/ISODateTime'
        comment:
          type: string
          maxLength: 2000

    LoyaltyTransactionType:
      type: string
      enum:
        - accrual
        - redemption
        - adjustment
        - expiration

    LoyaltyTransaction:
      type: object
      additionalProperties: false
      required:
        - id
        - type
        - points
        - created_at
      properties:
        id:
          $ref: '#/components/schemas/Id'
        type:
          $ref: '#/components/schemas/LoyaltyTransactionType'
        points:
          type: integer
          example: 150
        description:
          type:
            - string
            - 'null'
          maxLength: 1000
        related_booking_id:
          oneOf:
            - $ref: '#/components/schemas/Id'
            - type: 'null'
        created_at:
          $ref: '#/components/schemas/ISODateTime'
        expires_at:
          oneOf:
            - $ref: '#/components/schemas/ISODateTime'
            - type: 'null'

    LoyaltyAccount:
      type: object
      additionalProperties: false
      required:
        - client_id
        - current_balance
        - available_balance
        - lifetime_earned
        - lifetime_redeemed
        - updated_at
      properties:
        client_id:
          $ref: '#/components/schemas/Id'
        current_balance:
          type: integer
          minimum: 0
          example: 1200
        available_balance:
          type: integer
          minimum: 0
          example: 1000
        lifetime_earned:
          type: integer
          minimum: 0
          example: 5200
        lifetime_redeemed:
          type: integer
          minimum: 0
          example: 4000
        tier:
          type:
            - string
            - 'null'
          example: silver
        updated_at:
          $ref: '#/components/schemas/ISODateTime'

    LoyaltyAccountResponse:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          $ref: '#/components/schemas/LoyaltyAccount'

    LoyaltyTransactionListResponse:
      type: object
      additionalProperties: false
      required: [items, pagination]
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/LoyaltyTransaction'
        pagination:
          $ref: '#/components/schemas/Pagination'

    ErrorItem:
      type: object
      additionalProperties: false
      required: [field, reason]
      properties:
        field:
          type: string
          example: starts_at
        reason:
          type: string
          example: invalid_format

    ErrorEnvelope:
      type: object
      additionalProperties: false
      required: [code, message, request_id]
      properties:
        code:
          type: string
          example: bad_request
        message:
          type: string
          example: Request validation failed.
        request_id:
          type: string
          example: d750e3992a564eb6a0ae5dff1b273b01
        details:
          type: array
          items:
            $ref: '#/components/schemas/ErrorItem'

    ErrorResponse:
      type: object
      additionalProperties: false
      required: [error]
      properties:
        error:
          $ref: '#/components/schemas/ErrorEnvelope'