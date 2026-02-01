# 🐍 Python Assignment

## Ironclad Unified Inventory CLI

### Modeling and normalizing asset data across NetBox, Qualys, and EDR inventories

---

## Introduction

Ironclad Analytics has acquired multiple startups. Each startup used a different “source of truth” for asset inventory:

* **NetBox-style inventory** (network/infrastructure perspective)
* **Qualys-style inventory** (scanner/asset risk perspective)
* **EDR-style inventory** (endpoint runtime/identity perspective)

Your job is to build a **single CLI tool** that can pull inventory from all three systems, normalize the records into a consistent internal `Asset` model, and support analyst workflows like **pulling, listing, searching, and summarizing**.

> **Important:** This assignment is **inventory only**.
> We will extend it later to enrich assets with vulnerabilities and create Trello cards — **do not implement that yet**.

---

## Learning Objectives

You will practice:

* Fetching JSON from multiple APIs with `requests`
* Inspecting unfamiliar schemas and mapping fields correctly
* Designing classes with clean methods (OOP)
* Normalizing data into one consistent internal model
* Building a multi-command CLI with `argparse`
* Writing code designed to be extended later

---

## Provided Resources

Your instructor will provide three URLs in your classroom:

* `NETBOX_API_URL`
* `QUALYS_API_URL`
* `ENDPOINT_API_URL` (EDR-style)

---

# Part 0 — Setup

### Requirements

* Python 3.10+
* `requests`

Install:

```bash
python -m pip install requests
```

Create a file:

* `ironclad_inventory_cli.py`

---

# Part 1 — Walkthrough: Fetch + Inspect the JSON (Required)

### Goal

Before modeling anything, you must **inspect each dataset** to learn its field names.

Add this starter code:

```python
import requests
from typing import Any

NETBOX_API_URL = "PASTE_NETBOX_MOCKAROO_URL"
QUALYS_API_URL = "PASTE_QUALYS_MOCKAROO_URL"
ENDPOINT_API_URL = "PASTE_ENDPOINT_MOCKAROO_URL"


def fetch_json(url: str) -> list[dict[str, Any]]:
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"GET failed ({r.status_code}): {r.text[:200]}")
    data = r.json()
    if not isinstance(data, list):
        raise RuntimeError("Expected a list of records from the API.")
    # ensure dict-like records
    for i, rec in enumerate(data[:3]):
        if not isinstance(rec, dict):
            raise RuntimeError(f"Record {i} is not an object/dict.")
    return data


def preview_dataset(name: str, url: str) -> None:
    data = fetch_json(url)
    print(f"\n=== {name} PREVIEW ===")
    print(f"Records: {len(data)}")
    print("First record:")
    print(data[0])
    print("Fields:")
    for k in data[0].keys():
        print(" -", k)


if __name__ == "__main__":
    preview_dataset("NETBOX", NETBOX_API_URL)
    preview_dataset("QUALYS", QUALYS_API_URL)
    preview_dataset("ENDPOINT", ENDPOINT_API_URL)
```

✅ **Deliverable checkpoint:** Run the script and paste output (or screenshot) showing:

* first record
* field list
  for **each** source.

---

# Part 2 — Walkthrough: Build the Core Classes (Classes First)

## Step 2.1 — Define the normalized `Asset` model

Replace your `__main__` block temporarily with class definitions (you’ll add CLI later).

```python
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Asset:
    """
    Ironclad normalized asset model.
    Every inventory record from any source must be converted into this shape.
    """
    asset_id: str
    hostname: str
    ip_address: Optional[str]
    os: Optional[str]
    environment: Optional[str]
    owner_context: Optional[str]  # team, group, or user (depends on source)
    source: str                   # "netbox" | "qualys" | "endpoint"
    raw: dict[str, Any]           # original record for traceability

    def matches(self, query: str) -> bool:
        q = query.lower()
        values = [
            self.asset_id,
            self.hostname,
            self.ip_address or "",
            self.os or "",
            self.environment or "",
            self.owner_context or "",
            self.source,
        ]
        return any(q in str(v).lower() for v in values)

    def summary(self) -> str:
        return (
            f"[{self.source}] {self.hostname} "
            f"ip={self.ip_address or 'n/a'} os={self.os or 'n/a'} "
            f"env={self.environment or 'n/a'} owner={self.owner_context or 'n/a'}"
        )
```

Why this matters:

* You’re defining a **single truth** inside your tool.
* Every source must adapt to *this*, not the other way around.

---

## Step 2.2 — Create an Inventory Source base class

```python
import requests
from typing import Any


class InventorySource:
    name: str = "base"

    def __init__(self, api_url: str):
        self.api_url = api_url

    def fetch_raw(self) -> list[dict[str, Any]]:
        r = requests.get(self.api_url, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"{self.name} fetch failed ({r.status_code}): {r.text[:200]}")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"{self.name} returned unexpected JSON (expected list).")
        return data

    def normalize(self, record: dict[str, Any]) -> Asset:
        """Override in subclasses to map record -> Asset."""
        raise NotImplementedError

    def fetch_assets(self) -> list[Asset]:
        raw = self.fetch_raw()
        return [self.normalize(rec) for rec in raw]
```

---

## Step 2.3 — Implement the 3 source adapters (Students map fields)

### NetBox adapter

```python
class NetboxInventorySource(InventorySource):
    name = "netbox"

    def normalize(self, record: dict[str, Any]) -> Asset:
        # TODO: Map NetBox schema fields based on your preview output.
        # Suggested schema fields (from your Mockaroo design):
        # id, device_name, primary_ip, platform, environment, tenant, ...
        return Asset(
            asset_id=str(record.get("id")),                 # TODO confirm key
            hostname=str(record.get("device_name")),        # TODO confirm key
            ip_address=record.get("primary_ip"),            # TODO confirm key
            os=record.get("platform"),                      # TODO confirm key
            environment=record.get("environment"),          # TODO confirm key
            owner_context=record.get("tenant"),             # TODO confirm key
            source=self.name,
            raw=record,
        )
```

### Qualys adapter

```python
class QualysInventorySource(InventorySource):
    name = "qualys"

    def normalize(self, record: dict[str, Any]) -> Asset:
        # TODO: Map Qualys schema fields based on your preview output.
        # Suggested schema fields:
        # asset_id (UUID), hostname, ip_address, operating_system, asset_group, criticality, ...
        return Asset(
            asset_id=str(record.get("asset_id")),           # TODO confirm key
            hostname=str(record.get("hostname")),           # TODO confirm key
            ip_address=record.get("ip_address"),            # TODO confirm key
            os=record.get("operating_system"),              # TODO confirm key
            environment=record.get("asset_group"),          # TODO map group -> environment
            owner_context=None,                             # TODO if your schema has owner/team, map it
            source=self.name,
            raw=record,
        )
```

### Endpoint/EDR adapter

```python
class EndpointInventorySource(InventorySource):
    name = "endpoint"

    def normalize(self, record: dict[str, Any]) -> Asset:
        # TODO: Map Endpoint schema fields based on your preview output.
        # Suggested schema fields:
        # sensor_id, hostname, local_ip, os_version, logged_in_user, policy_applied, ...
        return Asset(
            asset_id=str(record.get("sensor_id")),          # TODO confirm key
            hostname=str(record.get("hostname")),           # TODO confirm key
            ip_address=record.get("local_ip"),              # TODO choose local_ip as primary
            os=record.get("os_version"),                    # TODO confirm key
            environment=None,                               # TODO if you have env-like field, map it
            owner_context=record.get("logged_in_user"),     # TODO confirm key
            source=self.name,
            raw=record,
        )
```

✅ **Checkpoint:** Add a quick test function and run it:

```python
def quick_test():
    sources = {
        "netbox": NetboxInventorySource(NETBOX_API_URL),
        "qualys": QualysInventorySource(QUALYS_API_URL),
        "endpoint": EndpointInventorySource(ENDPOINT_API_URL),
    }

    for name, src in sources.items():
        assets = src.fetch_assets()
        print(f"\n{name}: pulled {len(assets)} assets")
        for a in assets[:3]:
            print(" ", a.summary())


if __name__ == "__main__":
    quick_test()
```

---

# Part 3 — Walkthrough: Inventory Manager (Composition)

```python
class InventoryManager:
    def __init__(self, sources: dict[str, InventorySource]):
        self.sources = sources
        self.assets: list[Asset] = []

    def pull(self, source: str) -> None:
        self.assets.clear()
        if source == "all":
            for src in self.sources.values():
                self.assets.extend(src.fetch_assets())
        else:
            if source not in self.sources:
                raise ValueError(f"Unknown source: {source}")
            self.assets.extend(self.sources[source].fetch_assets())

    def list_assets(self, source: str = "all") -> list[Asset]:
        if source == "all":
            return list(self.assets)
        return [a for a in self.assets if a.source == source]

    def search(self, query: str, source: str = "all") -> list[Asset]:
        return [a for a in self.list_assets(source) if a.matches(query)]

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {"total": len(self.assets)}
        for a in self.assets:
            counts[a.source] = counts.get(a.source, 0) + 1
        return counts
```

✅ **Checkpoint:** After pulling `all`, verify:

* `stats()["total"] > 0`
* counts by source make sense

---

# Part 4 — Walkthrough: Build the CLI (argparse)

Replace your `__main__` with a real CLI:

```python
import argparse


def build_manager() -> InventoryManager:
    sources = {
        "netbox": NetboxInventorySource(NETBOX_API_URL),
        "qualys": QualysInventorySource(QUALYS_API_URL),
        "endpoint": EndpointInventorySource(ENDPOINT_API_URL),
    }
    return InventoryManager(sources)


def cmd_pull(args) -> None:
    mgr = build_manager()
    mgr.pull(args.source)
    s = mgr.stats()
    print("Pulled inventory.")
    print("Stats:", s)


def cmd_list(args) -> None:
    mgr = build_manager()
    mgr.pull(args.source)  # simple: list always pulls fresh
    for a in mgr.list_assets(args.source):
        print(a.summary())


def cmd_search(args) -> None:
    mgr = build_manager()
    mgr.pull(args.source)
    results = mgr.search(args.query, args.source)
    print(f"Results: {len(results)}")
    for a in results[: args.limit]:
        print(a.summary())


def cmd_stats(args) -> None:
    mgr = build_manager()
    mgr.pull(args.source)
    print("Stats:", mgr.stats())


def main():
    p = argparse.ArgumentParser(prog="ironclad-inventory", description="Ironclad Unified Inventory CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pull = sub.add_parser("pull", help="Pull inventory from a source")
    p_pull.add_argument("--source", choices=["netbox", "qualys", "endpoint", "all"], default="all")
    p_pull.set_defaults(func=cmd_pull)

    p_list = sub.add_parser("list", help="List assets")
    p_list.add_argument("--source", choices=["netbox", "qualys", "endpoint", "all"], default="all")
    p_list.set_defaults(func=cmd_list)

    p_search = sub.add_parser("search", help="Search assets by keyword")
    p_search.add_argument("--source", choices=["netbox", "qualys", "endpoint", "all"], default="all")
    p_search.add_argument("--query", required=True)
    p_search.add_argument("--limit", type=int, default=50)
    p_search.set_defaults(func=cmd_search)

    p_stats = sub.add_parser("stats", help="Show counts by source")
    p_stats.add_argument("--source", choices=["netbox", "qualys", "endpoint", "all"], default="all")
    p_stats.set_defaults(func=cmd_stats)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

✅ Required CLI behaviors (demo in your submission):

```bash
python ironclad_inventory_cli.py pull --source all
python ironclad_inventory_cli.py list --source netbox
python ironclad_inventory_cli.py search --query windows --source all
python ironclad_inventory_cli.py stats --source all
```

---

# Part 5 — Required Student Work

## A) Schema mapping notes (graded)

In `README.md`, include a section:

* **NetBox mapping:** `device_name → hostname`, `primary_ip → ip_address`, etc.
* **Qualys mapping:** `operating_system → os`, `asset_group → environment`, etc.
* **Endpoint mapping:** `local_ip → ip_address`, `logged_in_user → owner_context`, etc.

## B) Output quality

Your `Asset.summary()` should look consistent across sources.

---

# Part 6 — Challenge Extensions (Choose 3)

### Challenge A — Deduplicate by hostname

If hostname matches across sources, treat as the same asset and keep a list of sources seen.

### Challenge B — Filters on `list`

Add optional flags:

* `--os`
* `--environment`
* `--owner`

### Challenge C — Output formats

Support:

* `--format table` (default)
* `--format json`

### Challenge D — Find by IP

Add:

```bash
python ironclad_inventory_cli.py find-ip --ip 10.0.0.5
```

### Challenge E — Cache to disk

Save pulled normalized assets to `inventory_cache.json` and allow `--from-cache`.

---

# Deliverables

Submit:

1. `ironclad_inventory_cli.py`
2. `README.md` containing:

   * how to run each CLI command
   * your schema field mapping notes
   * which 3 challenges you completed
3. Terminal output (paste or screenshot) showing:

   * pull all
   * list one source
   * search across all
   * stats

---

# Rubric (100 points)

* 15 — JSON inspection + mapping notes are correct and thoughtful
* 20 — `Asset` class design + methods (`matches`, `summary`) are solid
* 20 — Source adapters correctly normalize each schema
* 15 — `InventoryManager` functions correctly
* 15 — CLI works (`pull`, `list`, `search`, `stats`)
* 15 — Three challenges completed and documented

---

## Future Extension Readiness (Do not implement yet)

Your design should make it easy to later add:

* `Vulnerability` objects tied to `Asset`
* vulnerability enrichment API calls
* Trello card creation for prioritized items

Stop at inventory normalization and CLI operations for this assignment.
