# 0001. System Overview

Status: Accepted  
Date: 2026-03-22  
Authors: Reva Studio Architecture  
Decision Type: Foundational Architecture Record

## 1. Context

Reva Studio is being designed as a production-grade digital platform for the beauty industry.

At the current stage, the platform serves a real beauty studio with approximately 8 specialists and covers operational workflows for services such as manicure, pedicure, lashes, brows, makeup, and massage. The target direction is broader than a single internal automation tool. The system is intended to evolve into a scalable SaaS and marketplace platform for multiple beauty businesses.

This document defines the system at the highest architectural level and fixes the baseline understanding of the product, its scope, core actors, boundaries, and strategic technical direction.

This overview is based on the project requirements established in the current working dialogue for Reva Studio.

## 2. Vision

Reva Studio is a unified beauty operations platform that combines:

- online booking
- client profiles
- staff and schedule management
- loyalty and rewards
- payments
- notifications
- analytics
- marketing workflows
- AI-assisted interactions
- Telegram and web access channels
- multi-tenant scalability for future salon onboarding

The long-term goal is to build a platform that starts from one operating studio and matures into a reusable software product for many salons.

## 3. Product Thesis

Reva Studio is not treated as a one-off studio bot or a narrow internal CRM.

It is designed as a business platform with three layers of value:

1. Operational value  
   Improves booking, staff load, communication, retention, and service delivery.

2. Managerial value  
   Gives visibility into utilization, revenue dynamics, customer activity, promotions, and loyalty effectiveness.

3. Platform value  
   Creates a software foundation that can later support many salons, separate client spaces, configurable rules, and partner expansion.

## 4. Primary Business Goals

The system must support the following business goals:

- reduce manual coordination around appointments
- improve slot utilization and staff workload distribution
- centralize client, booking, and service data
- improve repeat visits through loyalty and personalized offers
- standardize communications and reminders
- prepare the product for SaaS expansion beyond a single studio
- establish a technical base for future marketplace and partner workflows

## 5. Strategic Scope

### 5.1 Initial Scope

The initial scope covers the operating needs of one real studio:

- client registration and profile management
- service catalog
- specialist profiles
- working schedules
- appointment booking and rescheduling
- booking confirmation and reminder notifications
- loyalty balance and reward logic
- administrative control over services, staff, schedules, and bookings
- operational analytics

### 5.2 Target Scope

The target scope extends the system into a broader platform:

- multi-tenant salon support
- tenant-isolated data and configuration
- advanced customer segmentation
- marketing automation
- personalized recommendations
- richer analytics and business intelligence
- payment integrations
- Telegram Mini App
- marketplace-style expansion for external salons and partners
- tokenized bonus models if approved in later architecture decisions

## 6. Core Users and Actors

### 6.1 Client

A client is an end user who interacts with the platform to:

- browse services
- choose specialists
- view available slots
- create and manage appointments
- receive reminders and updates
- accumulate and spend loyalty rewards
- view personal activity history

### 6.2 Specialist

A specialist is a service provider within the studio who needs:

- personal schedule visibility
- appointment visibility
- status management for sessions
- workload clarity
- service and availability constraints

### 6.3 Administrator

An administrator manages operational control:

- services
- pricing
- schedules
- staff profiles
- booking adjustments
- loyalty rules
- promotions
- reporting
- customer communication workflows

### 6.4 Platform Operator

A platform operator appears in the future SaaS stage and manages:

- tenant onboarding
- tenant configuration
- operational governance
- platform-wide observability
- support and incident response

## 7. System Capabilities

The platform is expected to provide the following capabilities.

### 7.1 Client Domain Capabilities

- client profile creation
- personal history of interactions
- preferences and activity tracking
- loyalty state
- communication preferences

### 7.2 Booking Domain Capabilities

- service selection
- specialist selection
- time-slot discovery
- booking creation
- booking confirmation
- rescheduling
- cancellation
- booking status lifecycle

### 7.3 Staff Domain Capabilities

- specialist profile management
- working hours
- exceptions and time off
- supported services
- capacity rules

### 7.4 Catalog Domain Capabilities

- service categories
- service duration
- pricing
- service availability rules
- specialist-service compatibility

### 7.5 Loyalty Domain Capabilities

- individual bonus balance
- accrual rules
- redemption rules
- client-specific promotions
- future extensibility toward token-based rewards

### 7.6 Notifications Domain Capabilities

- reminders
- booking confirmations
- reschedule notices
- promotional messages
- operational alerts

### 7.7 Analytics Domain Capabilities

- booking volume
- staff utilization
- client retention indicators
- service popularity
- campaign effectiveness
- revenue-oriented operational metrics

## 8. Product Channels

The system is designed to support multiple interaction channels.

### 8.1 Telegram

Telegram is a primary operational channel for fast client interaction and convenient appointment workflows.

Expected forms:
- bot-based flows
- notifications
- client self-service actions
- future Telegram Mini App support

### 8.2 Web Admin Interface

A web-based administrative interface is required for structured business operations, including:

- managing staff
- managing services
- managing bookings
- managing loyalty
- viewing analytics
- executing manual interventions

### 8.3 Future Web Client Interface

A broader client-facing web experience may be introduced later for discovery, self-service, loyalty, and account access.

## 9. Architecture Principles

The system must follow these architecture principles.

### 9.1 Production-First Design

The project is built as a production-capable system from the beginning, not as a throwaway prototype.

### 9.2 Modular Growth

The system should start as a modular monolith and preserve clear boundaries so that high-load or fast-changing areas can later be extracted if needed.

### 9.3 Domain Clarity

Business domains must be separated explicitly to reduce coupling and preserve maintainability.

### 9.4 Tenant Readiness

Even before full multi-tenancy is activated, the system must avoid architectural choices that would block tenant isolation later.

### 9.5 Operational Reliability

Booking, schedule, and customer state must be consistent and observable.

### 9.6 Auditability

Changes affecting bookings, schedules, loyalty, and administrative actions should be traceable.

### 9.7 Security by Design

Authentication, authorization, data isolation, and secrets handling must be treated as architectural concerns, not afterthoughts.

## 10. Proposed High-Level Architecture

The system is structured around a backend-centric architecture with multiple access channels.

```text
Clients / Staff / Admins
        |
        v
Telegram Bot / Mini App / Web Admin
        |
        v
API Layer
        |
        v
Application Services
        |
        v
Domain Modules
        |
        +---- PostgreSQL
        +---- Redis
        +---- Background Jobs / Scheduler
        +---- Notification Providers
        +---- Analytics Pipelines