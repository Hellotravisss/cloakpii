"""Database source connectors.

Exports tables from a database to CSV files so the standard CloakPII pipeline
can desensitize + encrypt them:

    cloakpii db-export --url postgresql://user:pw@host/db --output ./dump
    cloakpii migrate    --source ./dump --output ./safe --compliance-profile pipl

SQLite needs no extra dependency (stdlib ``sqlite3``). PostgreSQL and MySQL
drivers are optional and imported lazily, so the base install stays lightweight:

    pip install cloakpii[postgres]   # psycopg
    pip install cloakpii[mysql]      # PyMySQL

Rows are streamed in batches, so even large tables export in constant memory.
"""

from __future__ import annotations

import csv
from pathlib import Path
from urllib.parse import urlparse

_FETCH_BATCH = 5000


class DBError(Exception):
    """Raised for database connection/export problems."""


def _scheme(url: str) -> str:
    return urlparse(url).scheme.lower().split("+")[0]


def _connect(url: str):
    """Open a DBAPI connection for a database URL. Returns (conn, scheme)."""
    scheme = _scheme(url)
    if scheme in ("sqlite", "sqlite3"):
        import sqlite3
        path = url.split("://", 1)[1] if "://" in url else url
        return sqlite3.connect(path), "sqlite"
    if scheme in ("postgresql", "postgres"):
        try:
            import psycopg  # type: ignore
        except ImportError as exc:
            raise DBError(
                "PostgreSQL support needs the 'psycopg' driver. "
                "Install it with: pip install cloakpii[postgres]"
            ) from exc
        return psycopg.connect(url), "postgresql"
    if scheme == "mysql":
        try:
            import pymysql  # type: ignore
        except ImportError as exc:
            raise DBError(
                "MySQL support needs the 'PyMySQL' driver. "
                "Install it with: pip install cloakpii[mysql]"
            ) from exc
        p = urlparse(url)
        return (
            pymysql.connect(
                host=p.hostname or "localhost",
                port=p.port or 3306,
                user=p.username,
                password=p.password,
                database=(p.path or "/").lstrip("/"),
            ),
            "mysql",
        )
    raise DBError(f"Unsupported database URL scheme: {scheme!r}")


def _quote(identifier: str, scheme: str) -> str:
    """Quote a table identifier for the given dialect (validated as an identifier)."""
    if not identifier.isidentifier():
        raise DBError(f"Refusing unsafe table name: {identifier!r}")
    if scheme == "mysql":
        return f"`{identifier}`"
    return f'"{identifier}"'


def list_tables(conn, scheme: str) -> list[str]:
    """Return the user table names for a connection."""
    cur = conn.cursor()
    if scheme == "sqlite":
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%';")
    elif scheme == "postgresql":
        cur.execute("SELECT tablename FROM pg_catalog.pg_tables "
                    "WHERE schemaname NOT IN ('pg_catalog', 'information_schema');")
    elif scheme == "mysql":
        cur.execute("SHOW TABLES;")
    else:
        raise DBError(f"Unsupported scheme: {scheme}")
    return [row[0] for row in cur.fetchall()]


def export_table_to_csv(conn, scheme: str, table: str, out_path: Path) -> int:
    """Stream one table to a CSV file. Returns the number of rows written."""
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {_quote(table, scheme)};")
    columns = [d[0] for d in cur.description]
    rows_written = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        while True:
            batch = cur.fetchmany(_FETCH_BATCH)
            if not batch:
                break
            writer.writerows(batch)
            rows_written += len(batch)
    return rows_written


def export_database(url: str, output_dir: Path, tables: list[str] | None = None) -> dict:
    """Export all (or selected) tables from a database to CSV files in output_dir.

    Returns a summary dict: ``{"tables": [{"table","rows","path"}...], "total_rows"}``.
    """
    output_dir = Path(output_dir)
    conn, scheme = _connect(url)
    try:
        names = tables or list_tables(conn, scheme)
        results = []
        total = 0
        for name in names:
            out_path = output_dir / f"{name}.csv"
            rows = export_table_to_csv(conn, scheme, name, out_path)
            results.append({"table": name, "rows": rows, "path": str(out_path)})
            total += rows
        return {"tables": results, "total_rows": total}
    finally:
        conn.close()
