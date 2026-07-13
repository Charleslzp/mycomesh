from __future__ import annotations

import importlib
import math
import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


POSTGRES_SCHEMES = {"postgres", "postgresql"}


class DatabaseConfigurationError(RuntimeError):
    """Raised when a configured database cannot be used safely."""


@dataclass(frozen=True)
class DatabaseTarget:
    value: str
    dialect: str

    @classmethod
    def parse(cls, value: str | Path) -> "DatabaseTarget":
        raw = str(value)
        scheme = urlsplit(raw).scheme.lower()
        if scheme in POSTGRES_SCHEMES:
            return cls(value=raw, dialect="postgresql")
        if "://" in raw:
            raise DatabaseConfigurationError(
                f"unsupported billing database URL scheme: {scheme or '<missing>'}"
            )
        return cls(value=raw, dialect="sqlite")


class PostgreSQLRow(Mapping[str, Any]):
    """Small sqlite3.Row-compatible view over a PostgreSQL result row."""

    def __init__(self, columns: Sequence[str], values: Sequence[Any]) -> None:
        self._columns = tuple(columns)
        self._values = tuple(values)
        self._index = {name: index for index, name in enumerate(self._columns)}

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._index[key]]

    def __iter__(self) -> Iterator[str]:
        return iter(self._columns)

    def __len__(self) -> int:
        return len(self._columns)

    def keys(self) -> tuple[str, ...]:
        return self._columns


class PostgreSQLCursor:
    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount)

    def fetchone(self) -> PostgreSQLRow | None:
        row = self._cursor.fetchone()
        return self._wrap(row)

    def fetchall(self) -> list[PostgreSQLRow]:
        return [self._wrap(row) for row in self._cursor.fetchall()]

    def __iter__(self) -> Iterator[PostgreSQLRow]:
        for row in self._cursor:
            wrapped = self._wrap(row)
            if wrapped is not None:
                yield wrapped

    def _wrap(self, row: Sequence[Any] | None) -> PostgreSQLRow | None:
        if row is None:
            return None
        description = self._cursor.description or ()
        columns = [str(item.name if hasattr(item, "name") else item[0]) for item in description]
        return PostgreSQLRow(columns, row)


class PostgreSQLConnection:
    dialect = "postgresql"

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def __enter__(self) -> "PostgreSQLConnection":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc_type is None:
                self._connection.commit()
            else:
                self._connection.rollback()
        finally:
            self._connection.close()

    def execute(self, sql: str, parameters: Sequence[object] = ()) -> PostgreSQLCursor:
        translated_sql, translated_parameters = _translate_postgresql(sql, parameters)
        cursor = self._connection.execute(translated_sql, translated_parameters)
        return PostgreSQLCursor(cursor)


def connect_database(target: DatabaseTarget, *, timeout_seconds: float = 5.0) -> Any:
    if target.dialect == "sqlite":
        path = Path(target.value)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=float(timeout_seconds))
        conn.row_factory = sqlite3.Row
        return conn
    return _connect_postgresql(target.value, timeout_seconds=timeout_seconds)


def _connect_postgresql(dsn: str, *, timeout_seconds: float) -> PostgreSQLConnection:
    try:
        psycopg = importlib.import_module("psycopg")
    except (ImportError, ModuleNotFoundError) as exc:
        raise DatabaseConfigurationError(
            "PostgreSQL billing requires psycopg 3; install the psycopg[binary] dependency"
        ) from exc
    version = str(getattr(psycopg, "__version__", "3"))
    if version.split(".", 1)[0] != "3":
        raise DatabaseConfigurationError("PostgreSQL billing requires psycopg major version 3")
    try:
        raw = psycopg.connect(
            dsn,
            autocommit=False,
            connect_timeout=max(1, int(math.ceil(float(timeout_seconds)))),
        )
    except Exception as exc:
        raise DatabaseConfigurationError("unable to connect to the configured PostgreSQL billing database") from exc
    return PostgreSQLConnection(raw)


_PRAGMA_TABLE_INFO = re.compile(
    r"^\s*PRAGMA\s+table_info\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$",
    re.IGNORECASE,
)


def _translate_postgresql(
    sql: str,
    parameters: Sequence[object],
) -> tuple[str, tuple[object, ...]]:
    pragma_match = _PRAGMA_TABLE_INFO.fullmatch(sql)
    if pragma_match:
        return (
            "SELECT column_name AS name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s ORDER BY ordinal_position",
            (pragma_match.group(1),),
        )

    normalized = sql.strip()
    if normalized.upper() in {"BEGIN IMMEDIATE", "BEGIN EXCLUSIVE"}:
        return "BEGIN", ()

    translated = _translate_qmark_placeholders(sql)
    if normalized.upper().startswith(("CREATE TABLE", "ALTER TABLE")):
        translated = re.sub(r"\bINTEGER\b", "BIGINT", translated, flags=re.IGNORECASE)
    translated = translated.replace(
        "MAX(0, pending_spend_units - %s)",
        "GREATEST(0, pending_spend_units - %s)",
    )
    return translated, tuple(parameters)


def _translate_qmark_placeholders(sql: str) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(sql):
        character = sql[index]
        if quote is not None:
            output.append(character)
            if character == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(character)
        elif character == "?":
            output.append("%s")
        else:
            output.append(character)
        index += 1
    return "".join(output)
