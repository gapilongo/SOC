"""User-reported email ingestion: MIME parsing into a bounded document (see :mod:`.parser`)."""

from lg_sotf.ingestion.email.parser import (
    SCHEMA,
    EmailLimits,
    EmailParseError,
    EmailTooLarge,
    parse_email,
    unparsed_email,
)

__all__ = ["SCHEMA", "EmailLimits", "EmailParseError", "EmailTooLarge", "parse_email", "unparsed_email"]
