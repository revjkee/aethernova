Backup and Restore Runbook
Status

Approved

Owner

Platform Operations

Last Reviewed

2026-03-23

Purpose

This runbook defines the production backup, restore, and recovery procedure for Reva Studio. It covers:

PostgreSQL logical backups
PostgreSQL physical backups
PostgreSQL point-in-time recovery
Redis persistence backup and restore
backup validation
restore drills
escalation and acceptance criteria

PostgreSQL officially documents three different backup approaches: SQL dump, file system level backup, and continuous archiving. They solve different recovery objectives and must not be treated as interchangeable.

Scope

This runbook applies to all environments that store business or customer data:

production
staging containing production-like data
disaster recovery environments
pre-production recovery test environments

This runbook does not replace:

infrastructure-as-code recreation
secrets rotation procedures
object storage lifecycle policies
incident response procedures
Recovery Objectives

Set and approve these values per environment.

Environment	RPO target	RTO target	Backup class
production	15 minutes	60 minutes	physical + WAL + logical export
staging	24 hours	4 hours	logical + optional physical
development	best effort	best effort	logical

RPO means maximum tolerated data loss measured backward from the failure point.
RTO means maximum tolerated restoration time until service is operational.

Roles
Incident Commander
declares restore event
approves restore target and cutover
coordinates communications
Database Operator
executes PostgreSQL backup and restore steps
validates backup integrity
records timing and checksums
Application Operator
puts application into maintenance mode
blocks writes during cutover when required
validates application health after restore
Security Reviewer
verifies access to backup storage
verifies audit trail and operator identity
approves sensitive data restore into non-production environments
Recovery Strategy

Reva Studio uses a layered strategy:

Logical backups for object-level restore and cross-environment portability.
Physical base backups for full cluster recovery.
WAL archiving for point-in-time recovery.
Regular restore drills to prove backups are usable.

PostgreSQL documents that pg_dump plus pg_restore is appropriate for logical archive workflows, while pg_basebackup is used for base backup of a running cluster and continuous archiving is required for point-in-time recovery. PITR requires a continuous sequence of archived WAL files extending back to at least the start of the base backup.

Data Classification for Backup
Tier 1: Authoritative state

Back up with strict retention and restore drills:

PostgreSQL primary business database
migration state
tenant configuration data
financial and booking records
Tier 2: Operational state

Back up if the deployment depends on persistence:

Redis persistence files when Redis is used beyond disposable cache semantics
scheduler state if stored in Redis and operationally required

Redis supports persistence through RDB snapshots and AOF. When both are enabled, Redis uses the AOF file at startup because it is typically more complete.

Tier 3: Reconstructable state

May be recreated from code or upstream systems:

container images
ephemeral cache entries
derived analytics projections
stateless application replicas
Backup Storage Requirements

Backup storage must satisfy all of the following:

encrypted at rest
separate credentials from production runtime
immutable or append-only retention where possible
off-host and preferably off-zone replication
auditable access logs
routine restore validation

Kubernetes volume snapshots provide point-in-time copies of storage volumes and are useful before risky modifications, but database recovery still requires database-consistent procedures and should not rely on storage snapshots alone as the only control.

Naming Convention

Use this naming pattern for all backup artifacts:

<system>-<env>-<backup-type>-<utc-timestamp>-<git-sha-or-release>-<checksum>

Examples:

reva-prod-pgdump-20260323T021500Z-rvstd-9f8c1a2.dump
reva-prod-basebackup-20260323T020000Z-rvstd-9f8c1a2.tar.zst
reva-prod-redis-rdb-20260323T021700Z.rdb
Backup Schedule
PostgreSQL logical backup

Frequency:

nightly

Format:

pg_dump --format=custom

Retention:

30 days minimum

Reason:
The PostgreSQL documentation states that the custom and directory formats are the most flexible because pg_restore can inspect, reorder, and selectively restore objects.

PostgreSQL physical base backup

Frequency:

daily or more often if required by RPO/RTO

Tool:

pg_basebackup

Retention:

according to WAL retention and disaster recovery policy

Reason:
pg_basebackup is designed to take a base backup of a running PostgreSQL cluster and can be used for PITR and standby initialization.

WAL archiving

Frequency:

continuous

Requirement:

archive success monitoring must be active

Reason:
PostgreSQL PITR requires a continuous sequence of archived WAL files back to the start of the base backup.

Redis backup

Frequency:

aligned with Redis persistence mode and business criticality

Artifacts:

RDB snapshot
AOF files if enabled and required

Reason:
Redis persistence is based on RDB snapshots and AOF logging.

Pre-Backup Checks

Before any scheduled or manual backup:

Confirm correct environment and cluster identity.
Confirm available disk space on backup target.
Confirm network path to offsite backup storage.
Confirm PostgreSQL primary is reachable.
Confirm replica lag is within accepted threshold if backing up from replica.
Confirm WAL archiving is healthy for physical backup strategy.
Confirm no active incident affects backup consistency.

Health check examples:

pg_isready -h "${PGHOST}" -p "${PGPORT}" -d "${PGDATABASE}" -U "${PGUSER}"

pg_isready is the PostgreSQL utility for checking server connection status and returns an exit status describing the result.

Standard Operating Procedure: PostgreSQL Logical Backup
Objective

Create a portable logical backup for schema and data restore.

Command
export PGPASSWORD="${PGPASSWORD}"

pg_dump \
  --host="${PGHOST}" \
  --port="${PGPORT}" \
  --username="${PGUSER}" \
  --dbname="${PGDATABASE}" \
  --format=custom \
  --blobs \
  --verbose \
  --file="/backups/reva-prod-pgdump-$(date -u +%Y%m%dT%H%M%SZ).dump"
Post-Backup Actions
Compute checksum.
Upload artifact to backup storage.
Record artifact size, checksum, start time, end time.
Run test restore in isolated environment on schedule.
Mark backup status only after checksum and storage replication succeed.
Validation

Example checksum:

sha256sum /backups/reva-prod-pgdump-*.dump
Notes

Use logical backup for:

object-level restore
migration between environments
selective table or schema restore
audit snapshots before risky schema changes

PostgreSQL explicitly documents that pg_dump archives combined with pg_restore allow selective restore and inspection when using non-plain formats such as custom or directory.

Standard Operating Procedure: PostgreSQL Physical Base Backup
Objective

Create a full cluster backup suitable for disaster recovery and PITR.

Command
export PGPASSWORD="${PGPASSWORD}"

pg_basebackup \
  --pgdata="/backups/basebackup-$(date -u +%Y%m%dT%H%M%SZ)" \
  --format=plain \
  --checkpoint=fast \
  --wal-method=stream \
  --progress \
  --verbose \
  --host="${PGHOST}" \
  --port="${PGPORT}" \
  --username="${PGREPLUSER}"
Integrity Verification
pg_verifybackup "/backups/basebackup-20260323T020000Z"

pg_verifybackup checks the integrity of a cluster backup taken using pg_basebackup against the server-generated backup_manifest.

Required Conditions
WAL archiving or WAL capture strategy must be confirmed.
Backup storage must have sufficient capacity.
Replication credentials must be valid if required.
Backup must not be considered complete without verification and artifact registration.
Standard Operating Procedure: WAL Archiving
Objective

Enable point-in-time recovery.

Requirements
WAL archive destination must be durable and monitored.
Missing WAL segments must page an operator.
Retention policy must cover the recovery window.
Acceptance Rule

A base backup is not sufficient for PITR unless the corresponding WAL chain is complete. PostgreSQL states this requirement directly.

Standard Operating Procedure: PostgreSQL Logical Restore
Use Cases
restore a single database into clean target
object-level recovery
staging refresh
pre-migration rollback rehearsal
Restore Command
export PGPASSWORD="${PGPASSWORD}"

createdb \
  --host="${PGHOST}" \
  --port="${PGPORT}" \
  --username="${PGUSER}" \
  "${TARGET_DATABASE}"

pg_restore \
  --host="${PGHOST}" \
  --port="${PGPORT}" \
  --username="${PGUSER}" \
  --dbname="${TARGET_DATABASE}" \
  --clean \
  --if-exists \
  --no-owner \
  --verbose \
  "/backups/reva-prod-pgdump-20260323T021500Z.dump"

pg_restore reconstructs a PostgreSQL database from an archive created by pg_dump in a non-plain format and can restore selectively or reorder items.

Validation Checklist
Database opens successfully.
Migration version is correct.
Key tables exist.
Row counts are within expected range.
Smoke queries pass.
Application health checks pass against restored target.

Example smoke query:

psql "${DATABASE_URL}" -c "select now(), current_database();"
Standard Operating Procedure: PostgreSQL Point-in-Time Recovery
Use Cases
operator error
destructive migration
bad deployment
accidental delete or update
corruption discovered after base backup
Preconditions
valid base backup
complete WAL archive chain
recovery target time, transaction, or LSN approved
isolated recovery destination
application writes blocked during final cutover
Procedure
Stop target PostgreSQL instance.
Provision clean recovery host or volume.
Restore base backup into target data directory.
Configure restore command and recovery target.
Start PostgreSQL in recovery mode.
Allow replay until target is reached.
Validate data correctness.
Promote recovered instance if approved.
Repoint application traffic.
Capture final audit trail and incident timeline.

PostgreSQL documents continuous archiving and PITR as the mechanism for recovery to a prior state in time, provided the base backup and WAL archive are both available and continuous.

Minimum Validation Before Promotion
PostgreSQL starts without recovery error
expected recovery target reached
booking and payment tables pass smoke queries
application startup succeeds
no missing critical relations
no pending migration mismatch
Standard Operating Procedure: Redis Backup
Objective

Preserve Redis persisted state when Redis is part of operational recovery requirements.

Determine Persistence Mode

Inspect Redis configuration and record whether the instance uses:

RDB snapshots
AOF
both

Redis officially documents both RDB and AOF as persistence mechanisms. The SAVE command creates a synchronous RDB snapshot and SHUTDOWN SAVE can force a save on shutdown.

Safe Redis Snapshot Procedure

Preferred approach:

use configured persistence files and copy them from durable storage after confirming flush completion
avoid ad hoc file copies during uncontrolled write bursts

Controlled shutdown example when operationally acceptable:

redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" SHUTDOWN SAVE
Artifact Capture

Typical artifacts:

dump.rdb
append-only files if AOF is enabled
Restore Procedure
Stop Redis target.
Place restored persistence files into configured Redis data directory.
Verify file ownership and permissions.
Start Redis.
Verify expected keyspace and service connectivity.

Redis documentation states that when both persistence modes are present, AOF is typically loaded at startup because it is more complete.

Kubernetes Snapshot Procedure
When Allowed

Use Kubernetes volume snapshots only as an additional infrastructure-level layer, not as a substitute for database-aware PostgreSQL backup strategy.

Conditions
CSI driver supports snapshots
snapshot class is approved
database consistency step is completed first
snapshot metadata is recorded in incident log

Kubernetes documents VolumeSnapshot as a standardized point-in-time copy of a volume.

Post-Restore Validation

After any restore, all of the following must be completed.

Database Validation
psql "${DATABASE_URL}" -c "select current_database(), now();"
psql "${DATABASE_URL}" -c "select count(*) from alembic_version;"
Functional Validation
application boots successfully
login works for test account
booking creation dry-run succeeds in non-production validation
read-only dashboards load
background workers connect successfully
migrations report expected version
Data Validation
key table row counts sampled
latest expected business records present up to chosen recovery point
referential integrity spot checks completed
tenant isolation spot checks completed
Audit Validation
operator identity recorded
recovery target recorded
artifact checksums recorded
timestamps recorded
final approval recorded
Backup Drill Policy
Frequency
monthly logical restore drill
monthly physical restore validation
quarterly PITR drill
quarterly Redis recovery drill if Redis persistence is in scope
Drill Success Criteria

A drill is successful only if:

Backup artifact is located from documentation alone.
Restore completes without undocumented manual improvisation.
Validation checklist passes.
Measured RTO is recorded.
Gaps in documentation are fixed immediately after the drill.

A backup that has not been restored and validated is not considered operationally proven. PostgreSQL’s own tooling includes pg_verifybackup specifically to validate backup integrity rather than assuming success from backup completion alone.

Failure Modes and Response
Backup Artifact Missing
declare backup integrity incident
block risky maintenance
verify retention and replication jobs
restore from previous known-good artifact if necessary
WAL Chain Gap
declare PITR unavailable for affected interval
preserve current evidence
assess nearest recoverable point from available WAL and base backups

PostgreSQL states PITR requires a continuous sequence of archived WAL files.

Checksum Mismatch
do not mark backup as valid
quarantine artifact
re-run backup
investigate storage corruption or transfer issue
Restore Succeeds but App Fails
keep traffic blocked
compare migration version and environment configuration
validate secrets, endpoints, and background worker dependencies
do not cut over until application checks pass
Security Requirements
backup credentials must not be shared with application runtime credentials
restores into non-production with sensitive data require authorization
backup artifacts must have access logging
least privilege must be applied to restore operators
backup artifacts must not be copied to unmanaged personal devices
Retention Policy Template

Set values explicitly per environment.

Artifact	Minimum retention	Offsite copy	Immutable retention
logical backup	30 days	yes	recommended
physical base backup	14 days	yes	recommended
WAL archive	aligned to PITR window	yes	recommended
Redis persistence backup	7 to 30 days	if in scope	recommended
Runbook Completion Criteria

This runbook is considered successfully executed only when all conditions are true:

correct backup artifact identified
checksum verified
restore completed
validation checklist passed
business owner or incident commander approved cutover
measured RTO and effective recovery point recorded
post-incident notes captured
References
PostgreSQL Documentation, Chapter 25, Backup and Restore.
PostgreSQL Documentation, pg_dump.
PostgreSQL Documentation, pg_restore.
PostgreSQL Documentation, pg_basebackup.
PostgreSQL Documentation, Continuous Archiving and Point-in-Time Recovery.
PostgreSQL Documentation, pg_isready.
PostgreSQL Documentation, pg_verifybackup.
Redis Documentation, Persistence.
Redis Documentation, SAVE.
Redis Documentation, SHUTDOWN.
Kubernetes Documentation, Volume Snapshots.