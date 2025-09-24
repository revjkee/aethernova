# cybersecurity-core/cybersecurity/adversary_emulation/integrations/cloud/aws.py
"""
AWS integration for benign adversary emulation and telemetry verification.

Features:
- Safe EventBridge PutEvents (custom benign events)
- CloudWatch Logs put_log_events with auto-setup (create log group/stream, handle sequence tokens)
- CloudTrail LookupEvents for recent management activity verification
- STS GetCallerIdentity and optional AssumeRole
- EC2 DescribeRegions (enabled regions)
- IAM account alias discovery
- Retry with exponential backoff for throttling/5xx
- Strict guardrails: no destructive operations, no network exfiltration

Key AWS API references:
- STS GetCallerIdentity: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/get_caller_identity.html
- STS AssumeRole: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/assume_role.html
- EventBridge PutEvents: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/events/client/put_events.html
- CloudWatch Logs put_log_events: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/logs/client/put_log_events.html
- CloudTrail LookupEvents: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/lookup_events.html
- EC2 DescribeRegions: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_regions.html
- IAM list_account_aliases: https://boto3.amazonaws.com/v1/documentation/api/1.26.83/reference/services/iam/client/list_account_aliases.html
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, EndpointConnectionError

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

LOGGER = logging.getLogger("aethernova.aws")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Exceptions & helpers
# -----------------------------------------------------------------------------

class AWSIntegrationError(RuntimeError):
    """Base error for AWS integration."""


class PermissionDenied(AWSIntegrationError):
    """Raised when AWS denies an action."""


class ThrottlingError(AWSIntegrationError):
    """Raised when AWS throttles an action."""


def _is_retryable(error: Exception) -> bool:
    if isinstance(error, EndpointConnectionError):
        return True
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        # Common throttling/limit transient conditions
        return code in {
            "Throttling",
            "ThrottlingException",
            "TooManyRequestsException",
            "RequestLimitExceeded",
            "ServiceUnavailableException",
            "InternalFailure",
            "InternalError",
            "ServiceUnavailable",
            "ProvisionedThroughputExceededException",
        }
    return False


def retry(max_attempts: int = 7, base_delay: float = 0.5, max_delay: float = 8.0):
    """
    Simple exponential backoff retry decorator for transient AWS errors.
    Retries on throttling/5xx and endpoint connectivity issues.
    """
    def _wrap(fn):
        def _inner(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:
                    attempt += 1
                    if attempt >= max_attempts or not _is_retryable(exc):
                        raise
                    sleep = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    LOGGER.warning("Retryable error on %s attempt %d: %s; sleeping %.2fs",
                                   fn.__name__, attempt, exc, sleep)
                    time.sleep(sleep)
        return _inner
    return _wrap

# -----------------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class AWSIdentity:
    account_id: str
    arn: str
    user_id: str
    aliases: Tuple[str, ...]
    partition: str


@dataclass(frozen=True)
class EventBridgeResult:
    entry_ids: Tuple[str, ...]
    failed_count: int


@dataclass(frozen=True)
class CloudWatchPutLogResult:
    next_sequence_token: Optional[str]
    rejected_log_events_info: Optional[Dict[str, Any]]


# -----------------------------------------------------------------------------
# Core integration
# -----------------------------------------------------------------------------

class AWSIntegration:
    """
    Industrial-grade AWS integration with safe (benign) primitives for adversary emulation.

    Guardrails:
      - No destructive operations (only create benign events/logs and read metadata)
      - No remote command execution, no data exfiltration
      - Resource names are prefixed and correlation-id tagged
    """

    DEFAULT_EVENT_SOURCE = "aethernova.attack-sim"
    DEFAULT_DETAIL_TYPE = "Aethernova.BenignTest"
    DEFAULT_EVENT_BUS = "default"

    def __init__(
        self,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        session_name: Optional[str] = None,
        user_agent_suffix: str = "Aethernova-AttackSim/1.0",
    ) -> None:
        self._region = region
        self._profile = profile
        self._role_arn = role_arn
        self._external_id = external_id
        self._session_name = session_name or f"aethernova-session-{uuid.uuid4()}"
        self._user_agent_suffix = user_agent_suffix

        self._base_session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self._session = self._assume_if_needed(self._base_session)

        # shared config with reasonable timeouts/retries at botocore level
        self._config = BotoConfig(
            retries={"max_attempts": 10, "mode": "standard"},
            connect_timeout=5,
            read_timeout=60,
            user_agent_extra=self._user_agent_suffix,
        )

    # --------------------------- STS / Identity -------------------------------

    @retry()
    def _assume_if_needed(self, session: boto3.session.Session) -> boto3.session.Session:
        if not self._role_arn:
            return session
        sts = session.client("sts", config=BotoConfig(user_agent_extra=self._user_agent_suffix))
        assume_kwargs = {
            "RoleArn": self._role_arn,
            "RoleSessionName": self._session_name,
            "DurationSeconds": 3600,
        }
        if self._external_id:
            assume_kwargs["ExternalId"] = self._external_id
        resp = sts.assume_role(**assume_kwargs)
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self._region or session.region_name,
        )

    @retry()
    def get_identity(self) -> AWSIdentity:
        sts = self._session.client("sts", config=self._config)
        ident = sts.get_caller_identity()  # STS GetCallerIdentity does not require permissions (see docs)
        account = ident["Account"]
        arn = ident["Arn"]
        user_id = ident["UserId"]
        partition = arn.split(":")[1] if ":" in arn else "aws"

        aliases: Tuple[str, ...] = ()
        try:
            iam = self._session.client("iam", config=self._config)
            resp = iam.list_account_aliases()
            aliases = tuple(resp.get("AccountAliases", []) or [])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in {"AccessDenied", "AccessDeniedException"}:
                # Not critical; continue without aliases
                LOGGER.info("No IAM permissions to list_account_aliases; continuing without alias info.")
            else:
                raise
        return AWSIdentity(account_id=account, arn=arn, user_id=user_id, aliases=aliases, partition=partition)

    # --------------------------- Regions --------------------------------------

    @retry()
    def list_enabled_regions(self) -> Tuple[str, ...]:
        """
        Returns regions enabled for the account (per EC2 DescribeRegions default behavior).
        """
        ec2 = self._session.client("ec2", config=self._config)
        resp = ec2.describe_regions()  # default: regions available/enabled to the account
        return tuple(r["RegionName"] for r in resp.get("Regions", []))

    # --------------------------- EventBridge ----------------------------------

    @retry()
    def put_benign_event(
        self,
        detail: Dict[str, Any],
        detail_type: Optional[str] = None,
        source: Optional[str] = None,
        event_bus_name: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> EventBridgeResult:
        """
        Sends a benign custom event to EventBridge (PutEvents).
        """
        events = self._session.client("events", region_name=self._region, config=self._config)
        detail_type = detail_type or self.DEFAULT_DETAIL_TYPE
        source = source or self.DEFAULT_EVENT_SOURCE
        event_bus_name = event_bus_name or self.DEFAULT_EVENT_BUS
        correlation_id = correlation_id or str(uuid.uuid4())

        enriched = dict(detail)
        enriched.setdefault("correlation_id", correlation_id)
        enriched.setdefault("safety_mode", "benign")

        entries = [{
            "Source": source,
            "DetailType": detail_type,
            "Detail": json.dumps(enriched, separators=(",", ":")),
            "EventBusName": event_bus_name,
            "Time": datetime.now(timezone.utc),
        }]

        resp = events.put_events(Entries=entries)
        failed = int(resp.get("FailedEntryCount", 0))
        ids = tuple(eid for eid in (r.get("EventId") for r in resp.get("Entries", [])) if eid)
        return EventBridgeResult(entry_ids=ids, failed_count=failed)

    # --------------------------- CloudWatch Logs -------------------------------

    @retry()
    def _ensure_log_group(self, logs_client, log_group: str) -> None:
        try:
            logs_client.create_log_group(logGroupName=log_group)
            LOGGER.info("Created log group: %s", log_group)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in {"ResourceAlreadyExistsException"}:
                raise

    @retry()
    def _ensure_log_stream(self, logs_client, log_group: str, log_stream: str) -> None:
        try:
            logs_client.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
            LOGGER.info("Created log stream: %s/%s", log_group, log_stream)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in {"ResourceAlreadyExistsException"}:
                raise

    @retry()
    def _get_sequence_token(self, logs_client, log_group: str, log_stream: str) -> Optional[str]:
        resp = logs_client.describe_log_streams(
            logGroupName=log_group,
            logStreamNamePrefix=log_stream,
            limit=1,
        )
        streams = resp.get("logStreams", [])
        if not streams:
            return None
        return streams[0].get("uploadSequenceToken")

    @retry()
    def put_benign_cloudwatch_log(
        self,
        log_group: str,
        log_stream: str,
        message: str,
        correlation_id: Optional[str] = None,
    ) -> CloudWatchPutLogResult:
        """
        Writes a benign log event to CloudWatch Logs (put_log_events) with proper sequence token handling.
        """
        logs = self._session.client("logs", region_name=self._region, config=self._config)
        self._ensure_log_group(logs, log_group)
        self._ensure_log_stream(logs, log_group, log_stream)

        correlation_id = correlation_id or str(uuid.uuid4())
        payload = {
            "message": message,
            "correlation_id": correlation_id,
            "safety_mode": "benign",
            "ts": datetime.now(timezone.utc).isoformat(),
        }

        # obtain token (if exists)
        token = self._get_sequence_token(logs, log_group, log_stream)
        event = {
            "timestamp": int(time.time() * 1000),
            "message": json.dumps(payload, separators=(",", ":")),
        }

        try:
            kwargs = {
                "logGroupName": log_group,
                "logStreamName": log_stream,
                "logEvents": [event],
            }
            if token:
                kwargs["sequenceToken"] = token
            resp = logs.put_log_events(**kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            # Handle InvalidSequenceToken gracefully by refetching token
            if code == "InvalidSequenceTokenException":
                token = self._get_sequence_token(logs, log_group, log_stream)
                kwargs = {
                    "logGroupName": log_group,
                    "logStreamName": log_stream,
                    "logEvents": [event],
                }
                if token:
                    kwargs["sequenceToken"] = token
                resp = logs.put_log_events(**kwargs)
            else:
                raise

        return CloudWatchPutLogResult(
            next_sequence_token=resp.get("nextSequenceToken"),
            rejected_log_events_info=resp.get("rejectedLogEventsInfo"),
        )

    # --------------------------- CloudTrail -----------------------------------

    @retry()
    def cloudtrail_lookup_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        lookup_attributes: Optional[List[Dict[str, str]]] = None,
        max_results: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Looks up recent CloudTrail events (management or insights) within last 90 days.
        """
        start_time = start_time or datetime.now(timezone.utc) - timedelta(minutes=30)
        end_time = end_time or datetime.now(timezone.utc)
        ct = self._session.client("cloudtrail", region_name=self._region, config=self._config)

        kwargs: Dict[str, Any] = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": max_results,
        }
        if lookup_attributes:
            kwargs["LookupAttributes"] = lookup_attributes

        events: List[Dict[str, Any]] = []
        token = None
        while True:
            if token:
                kwargs["NextToken"] = token
            resp = ct.lookup_events(**kwargs)
            events.extend(resp.get("Events", []) or [])
            token = resp.get("NextToken")
            if not token:
                break
        return events

    # --------------------------- Utilities ------------------------------------

    def client(self, service: str):
        """Get a low-level client with shared config."""
        return self._session.client(service, region_name=self._region, config=self._config)

    def resource(self, service: str):
        """Get a resource object with shared config."""
        return self._session.resource(service, region_name=self._region, config=self._config)

# -----------------------------------------------------------------------------
# Example benign workflow builder (for runners to invoke)
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class BenignWorkflowResult:
    region: str
    identity: AWSIdentity
    eventbridge: EventBridgeResult
    cloudwatch: CloudWatchPutLogResult
    cloudtrail_sample: int


def run_benign_telemetry_probe(
    region: str,
    profile: Optional[str] = None,
    role_arn: Optional[str] = None,
    external_id: Optional[str] = None,
    event_bus: str = AWSIntegration.DEFAULT_EVENT_BUS,
    log_group: str = "/aethernova/attack-sim",
    log_stream_prefix: str = "benign",
) -> BenignWorkflowResult:
    """
    End-to-end benign telemetry probe:
      1) Resolve identity (STS)
      2) Send EventBridge benign event
      3) Write CloudWatch Logs benign record
      4) Lookup recent CloudTrail events (sample count for sanity)
    """
    integ = AWSIntegration(
        region=region, profile=profile, role_arn=role_arn, external_id=external_id
    )
    identity = integ.get_identity()
    corr = str(uuid.uuid4())

    eb = integ.put_benign_event(
        detail={"action": "telemetry_probe", "region": region},
        event_bus_name=event_bus,
        correlation_id=corr,
    )

    cw = integ.put_benign_cloudwatch_log(
        log_group=log_group,
        log_stream=f"{log_stream_prefix}-{datetime.now(timezone.utc).date()}",
        message="benign-telemetry-probe",
        correlation_id=corr,
    )

    # Filter sample CloudTrail by EventName=PutEvents for the correlation drift window
    events = integ.cloudtrail_lookup_events(
        start_time=datetime.now(timezone.utc) - timedelta(minutes=30),
        end_time=datetime.now(timezone.utc) + timedelta(minutes=5),
        lookup_attributes=[{"AttributeKey": "EventName", "AttributeValue": "PutEvents"}],
        max_results=10,
    )

    return BenignWorkflowResult(
        region=region,
        identity=identity,
        eventbridge=eb,
        cloudwatch=cw,
        cloudtrail_sample=len(events),
    )
