"""PandaProxy - BambuLab Camera Fan-Out Proxy.

A transparent proxy that maintains a single connection to BambuLab printer
camera streams and serves multiple clients via the same protocols.
"""

from pandaproxy._version import version

__version__ = version
