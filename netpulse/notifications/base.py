"""Notifier interface. Sending never raises: a failed alert must not stop monitoring."""

from __future__ import annotations

DEVICE_NOTICE_CATEGORY = "device_notice"


class Notifier:
    def send(self, text: str) -> None:
        raise NotImplementedError


class NullNotifier(Notifier):
    def send(self, text: str) -> None:
        pass

    def send_categorized(self, text: str, category: str) -> None:
        pass
