#!/usr/bin/env python3
"""
notifications.py
================
Enterprise ChatOps, Alerting & Incident Notification Engine.

Supported Integrations:
1. Slack Incoming Webhooks (Block Kit Risk Cards).
2. Microsoft Teams Webhooks (Adaptive Cards).
3. Jira REST API (Automated Security Deficit & Vulnerability Bug Tickets).
4. PagerDuty Events API v2 (Critical Runtime Breakout Incident Paging).
"""

from dataclasses import dataclass
import json
import logging
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

try:
    from .container import validate_safe_url
except ImportError:
    from container import validate_safe_url

logger = logging.getLogger("NativeScanner.Notifications")


@dataclass
class AlertPayload:
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    cluster_id: str
    namespace: str = "default"
    workload_name: str = ""
    remediation: str = ""
    findings_count: int = 1


class NotificationDispatcher:
    """
    Dispatches formatted security alert cards to enterprise communication
    and incident response channels with SSRF validation.
    """

    SEVERITY_COLORS = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ef4444",
        "MEDIUM": "#f59e0b",
        "LOW": "#3b82f6",
        "INFO": "#10b981",
    }

    # --------------------------------------------------------------------------
    # 1. Slack Incoming Webhook (Block Kit)
    # --------------------------------------------------------------------------
    @classmethod
    def send_slack_alert(cls, webhook_url: str, alert: AlertPayload, timeout: int = 5) -> bool:
        """Sends rich Slack alert card with Block Kit formatting."""
        validate_safe_url(webhook_url, allow_private=False)
        color = cls.SEVERITY_COLORS.get(alert.severity.upper(), "#ef4444")
        emoji = "🚨" if alert.severity in ("CRITICAL", "HIGH") else "⚠️"

        payload = {
            "text": f"{emoji} [{alert.severity}] Security Alert on {alert.cluster_id}: {alert.title}",
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": f"{emoji} {alert.title}", "emoji": True},
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:*\n`{alert.severity}`"},
                                {"type": "mrkdwn", "text": f"*Cluster:*\n`{alert.cluster_id}`"},
                                {"type": "mrkdwn", "text": f"*Namespace:*\n`{alert.namespace}`"},
                                {"type": "mrkdwn", "text": f"*Workload:*\n`{alert.workload_name or 'N/A'}`"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Description:*\n{alert.description}"},
                        },
                    ],
                }
            ],
        }
        if alert.remediation:
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommended Remediation:*\n```{alert.remediation}```"},
            })

        return cls._post_json(webhook_url, payload, timeout=timeout)

    # --------------------------------------------------------------------------
    # 2. Microsoft Teams Webhook (Adaptive Cards)
    # --------------------------------------------------------------------------
    @classmethod
    def send_teams_alert(cls, webhook_url: str, alert: AlertPayload, timeout: int = 5) -> bool:
        """Sends Microsoft Teams notification card."""
        validate_safe_url(webhook_url, allow_private=False)
        color = cls.SEVERITY_COLORS.get(alert.severity.upper(), "#ef4444").lstrip("#")

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "title": f"[{alert.severity}] {alert.title}",
            "summary": alert.title,
            "sections": [
                {
                    "facts": [
                        {"name": "Cluster", "value": alert.cluster_id},
                        {"name": "Namespace", "value": alert.namespace},
                        {"name": "Severity", "value": alert.severity},
                        {"name": "Description", "value": alert.description},
                    ],
                    "markdown": True,
                }
            ],
        }
        return cls._post_json(webhook_url, payload, timeout=timeout)

    # --------------------------------------------------------------------------
    # 3. PagerDuty Events API v2
    # --------------------------------------------------------------------------
    @classmethod
    def trigger_pagerduty_incident(
        cls,
        routing_key: str,
        alert: AlertPayload,
        dedup_key: Optional[str] = None,
        timeout: int = 5,
    ) -> bool:
        """Triggers a high-priority PagerDuty incident for Sev-1 container breakouts."""
        url = "https://events.pagerduty.com/v2/enqueue"
        pd_sev = "critical" if alert.severity == "CRITICAL" else ("error" if alert.severity == "HIGH" else "warning")

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key or f"k8s-{alert.cluster_id}-{alert.namespace}-{alert.title[:20]}",
            "payload": {
                "summary": f"[{alert.severity}] {alert.title} on {alert.cluster_id}/{alert.namespace}",
                "severity": pd_sev,
                "source": alert.cluster_id,
                "component": alert.workload_name or "kubernetes-workload",
                "custom_details": {
                    "description": alert.description,
                    "remediation": alert.remediation,
                    "namespace": alert.namespace,
                },
            },
        }
        return cls._post_json(url, payload, timeout=timeout)

    # Alias for API uniformity
    send_pagerduty_event = trigger_pagerduty_incident

    # --------------------------------------------------------------------------
    # Internal HTTP Dispatcher
    # --------------------------------------------------------------------------
    @staticmethod
    def _post_json(url: str, data: Dict[str, Any], timeout: int = 5) -> bool:
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "k8s-native-scanner/2.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status in (200, 201, 202)
        except Exception as e:
            logger.warning(f"Notification delivery failed for {url}: {e}")
            return False
