"""overstep — a matrix-driven authorization testing tool for HTTP APIs.

overstep takes a declarative *authorization matrix* (who is allowed to do what)
and turns it into concrete positive and negative HTTP tests. Negative tests that
unexpectedly succeed are reported as authorization vulnerabilities and classified
as BOLA, BFLA or privilege escalation. Results can be snapshotted so that CI can
fail on *authorization drift* between releases.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
