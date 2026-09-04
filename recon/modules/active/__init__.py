"""Active recon modules - only run after the passive-first checkpoint is cleared."""

from recon.modules.active import cve_correlate, dir_fuzz, port_scan, scan_diff  # noqa: F401

try:
    from recon.modules.active import dns_axfr  # noqa: F401
except ImportError:
    pass
try:
    from recon.modules.active import subdomain_brute  # noqa: F401
except ImportError:
    pass
