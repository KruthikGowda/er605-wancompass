"""Publicly stat-able lock markers; trial identities remain in root-private files."""
from pathlib import Path

TRIAL_JOURNAL = Path('/var/lib/netpulse/router-compat-trial/journal.json')
TRIAL_PENDING = Path('/var/lib/netpulse/router-compat-status/pending')


def trial_recovery_pending():
    try:
        TRIAL_PENDING.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True
