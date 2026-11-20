@AGENTS.md

## Project Notes

- Design System & Token Rules: `RULES.md` §5 and `frontend/src/styles/tokens.css`.
- In-Process RDP Engine: Pure-Rust `IronRDP 0.17` server-side native client (`crates/operquay-rdp`) with zero sidecar containers (`RULES.md` §1).
- Multi-Database OOP Architecture: `DatabaseEngineDriver` trait in `crates/operquay-db` supporting PostgreSQL, ClickHouse, DuckDB, MySQL, and Redis (`docs/ADR/0009`).
- Semantic index: `ccc search <query>` (updated via `ccc index`).
