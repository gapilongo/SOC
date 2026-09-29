"""Advisory lock namespaces.

Two-key advisory locks ``(class, key)`` keep application locks from colliding
with each other; each subsystem owns one class number.
"""

AUDIT_CHAIN = 710_001
PARTITION_MAINTENANCE = 710_002
RETENTION = 710_003
MIGRATIONS = 710_004
SCHEDULER_LEADER = 710_010
