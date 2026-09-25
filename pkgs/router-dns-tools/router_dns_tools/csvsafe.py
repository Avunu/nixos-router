"""CSV cells that a spreadsheet will not run.

Query-log exports carry text the network chose: domain names and answer rdata
(a TXT record is any string its owner likes). A cell starting with = + - @ or a
tab/CR is a formula to Excel, LibreOffice and Sheets, so opening an export could
run what a looked-up domain put there. Prefixing a quote keeps the text and
drops the formula (OWASP's CSV-injection guidance).
"""

from __future__ import annotations

from typing import Iterable

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def cell(value):
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def row(values: Iterable) -> list:
    return [cell(v) for v in values]
