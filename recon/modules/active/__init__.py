"""Active recon modules - only run after the passive-first checkpoint is cleared."""

from recon.modules.active import (  # noqa: F401
    cve_correlate,
    dir_fuzz,
    exposure_checks,
    port_scan,
    scan_diff,
)

try:
    from recon.modules.active import dns_axfr  # noqa: F401
except ImportError:
    pass
try:
    from recon.modules.active import subdomain_brute  # noqa: F401
except ImportError:
    pass
