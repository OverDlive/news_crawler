

"""
Unit‑tests for the *defense* helpers (ipset / suricata).

The tests are **offline‑only**: all external binaries and filesystem paths
are monkey‑patched so no privileged commands are executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest


# --------------------------------------------------------------------------- #
#  ipset helper
# --------------------------------------------------------------------------- #
def test_ipset_block_invokes_restore(monkeypatch):
    """
    Ensure `ipset.block()` composes a RESTORE payload that includes each IP.

    We monkey‑patch the internal `_run_ipset_cmd()` so no actual `ipset`
    binary is invoked.
    """
    import secbot.defense.ipset as ipset

    captured: List[bytes] = []

    def fake_run(args, *, input_=None, check=True):
        # Record the raw payload for later assertions
        if "restore" in args:
            captured.append(input_)
        class _Dummy:
            stdout = b""
            stderr = b""
        return _Dummy()

    monkeypatch.setattr(ipset, "_run_ipset_cmd", fake_run)
    # Speed‑bump: skip initial `ensure_set()` call
    monkeypatch.setattr(ipset, "ensure_set", lambda: None)

    ips = ["1.2.3.4", "5.6.7.8"]
    ipset.block(ips)

    assert captured, "ipset.restore was never called"
    payload = captured[0].decode()
    for ip in ips:
        assert f"add {ipset.SET_NAME} {ip}" in payload


# --------------------------------------------------------------------------- #
#  suricata helper
# --------------------------------------------------------------------------- #
def test_suricata_block_writes_rules(monkeypatch, tmp_path):
    """
    Verify that `suricata.block()` writes a rules file containing every IP
    and calls `_reload_suricata()` exactly once.
    """
    import secbot.defense.suricata as s

    rules_path = tmp_path / "secbot-blacklist.rules"
    reload_called = {"count": 0}

    monkeypatch.setattr(s, "RULES_PATH", rules_path)
    monkeypatch.setattr(s, "_reload_suricata", lambda: reload_called.update(count=1))

    ips = ["10.0.0.1", "10.0.0.2"]
    s.block(ips)

    # File should be created
    assert rules_path.exists()
    text = rules_path.read_text()
    for ip in ips:
        assert ip in text

    # Reload should be triggered once
    assert reload_called["count"] == 1