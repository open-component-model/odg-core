"""
Central audit-log emission for ODG.

Audit-relevant events (findings writes, rescorings, deletions, secret use, mutation requests)
are emitted via a dedicated structlog logger named `audit`. The logger name surfaces as the
scope/logger field in every log pipeline, so OpenSearch/Loki can route audit events to a
separate index with its own (longer) retention policy.

Emission is deliberately not configurable: audit events must never be muted at runtime.
Mute capabilities would break the evidentiary value of the audit trail (and get flagged by
compliance audits); volume and retention are controlled downstream in the log pipeline.

Field naming follows the OpenTelemetry semantic-convention naming rules: application-specific
fields are prefixed with the application namespace (`odg.audit.*`, snake_case rendered by
structlog as `odg_audit_*`), fields with an existing OTel semantic convention reuse it
(`event_name` -> `event.name`, `user_id` -> `user.id`).
"""

import enum
import json
import collections.abc

import structlog

logger = structlog.get_logger('audit')

_EVENT_NAME_PREFIX = 'odg.audit'

# guard against unbounded audit events (e.g. bulk writes with many entries)
MAX_DETAIL_ITEMS = 25
MAX_DETAIL_LENGTH = 2000


class Outcome(enum.StrEnum):
    ALLOWED = 'allowed'
    DENIED = 'denied'
    ERROR = 'error'
    NOT_FOUND = 'not_found'


def capped(
    values: collections.abc.Iterable[str],
    limit: int = MAX_DETAIL_ITEMS,
) -> dict:
    """
    Serialise a list of identifiers for audit details: keep at most `limit` items and record
    the total count, so bulk operations do not produce unbounded log payloads.
    """
    values = sorted(values)

    return {
        'total': len(values),
        'items': values[:limit],
    }


def stringify(value) -> str:
    """
    Serialise a (potentially large or non-JSON) value for `old_value`/`new_value` fields.
    The result is capped at `MAX_DETAIL_LENGTH` chars; the full value lives in the delivery-db.
    """
    serialised = json.dumps(value, default=str, sort_keys=True)

    if len(serialised) > MAX_DETAIL_LENGTH:
        return f'{serialised[:MAX_DETAIL_LENGTH]}...<truncated>'

    return serialised


def emit(
    action: str,
    *,
    msg: str | None = None,
    **fields,
):
    """
    Emit an audit event on the `audit` logger.

    `action` is a snake_case verb (e.g. `findings_write`); it is emitted both as the
    OTel-style event name (`odg.audit.<action>`) and as `odg_audit_action`. All other values
    are passed as dict kwargs (never f-strings) so they become queryable JSON fields.

    Rename note: rename `action` verbs only with care; downstream log-pipeline routing and
    dashboards may filter on `event_name`/`odg_audit_action` values.
    """
    if msg is None:
        msg = action.replace('_', ' ')

    logger.info(
        msg,
        event_name=f'{_EVENT_NAME_PREFIX}.{action}',
        odg_audit_action=action,
        **fields,
    )
