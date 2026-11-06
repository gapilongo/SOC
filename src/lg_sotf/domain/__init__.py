"""Domain policy and ports: pure functions and value types with no I/O.

Lower layers (``db``, ``audit``, adapters) and the application import these
rules instead of reaching up into the workflow engine (docs/adr/0001-layering.md).
Importing this package loads nothing; import the submodules explicitly.
"""
