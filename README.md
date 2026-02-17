# 🛡️ Assignment: From Vulnerability to Ticket

## Extending the Ironclad Unified Inventory CLI

---

## 📘 Scenario

Ironclad Analytics now has a unified inventory across multiple systems. Leadership’s next question:

> “Which of our assets are vulnerable — and who is fixing them?”

Your team has been asked to:

1. Pull vulnerability findings from a new API endpoint
2. Correlate those findings to known inventory assets
3. Prioritize vulnerabilities based on risk
4. Create Trello cards to simulate remediation tickets

This assignment models how real security teams operationalize vulnerability data.

---
Reference: You can find docs on how to get and setup the values used from Trello in [the trello docs of this repo](./docs/trello_setting_up_api_access.md). You WILL need to setup an account for Trello for this assignment.

## 🎯 Learning Objectives

By completing this assignment, you will:

* Correlate security findings to asset inventory
* Derive severity from CVSS scores
* Apply risk-based prioritization logic
* Integrate with a third-party REST API (Trello)
* Generate structured remediation tickets
* Simulate a real vulnerability management workflow

---

# 🧩 Part 1 — Walkthrough

This section guides you through the core functionality.

---

### A) Vulnerability API endpoint

Add a new Mockaroo URL like:

```python
VULN_API_URL = "https://my.api.mockaroo.com/ironclad/vulns/findings.json"
```

Your dataset should include fields that can tie back to inventory, e.g.:

* `asset_hostname` (preferred)
* `asset_ip` (fallback)
* `cve_id`
* `severity`
* `cvss_score`
* `exploit_available`
* `recommended_fix`
* `status`

### B) Trello credentials (as environment variables)

Students should set these:

```bash
export TRELLO_KEY="..."
export TRELLO_TOKEN="..."
export TRELLO_BOARD_ID="..."
export TRELLO_LIST_ID="..."   # e.g., "Backlog"
```

---

## 1) Step: Create a `Vulnerability` class

Create a new file: **`vulnerability.py`**

```python
from typing import Any, Optional

class Vulnerability:
    def __init__(self, raw: dict[str, Any]):
        self.raw = raw

        # TODO: map these keys to your Mockaroo vuln schema
        self.cve_id: str = raw.get("cve_id", "UNKNOWN-CVE")
        self.title: str = raw.get("vuln_title", "Untitled Vulnerability")

        self.cvss_score: Optional[float] = raw.get("cvss_score")
        self.exploit_available: bool = bool(raw.get("exploit_available", False))
        self.recommended_fix: str = raw.get("recommended_fix", "")

        # These tie back to assets
        self.asset_hostname: str = raw.get("asset_hostname", "")
        self.asset_ip: Optional[str] = raw.get("asset_ip")

        # Optional fields if you include them
        self.status: str = raw.get("status", "open")

    def key(self) -> str:
        """Used for deduping: same vuln on same host."""
        return f"{self.asset_hostname}|{self.cve_id}"

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.cve_id} on {self.asset_hostname}"
```

---

## 2) Step: Pull vulnerabilities from the new API

Create a new file: **`vulnerability_source.py`**

```python
import requests
from typing import Any
from vulnerability import Vulnerability

class VulnerabilitySource:
    def __init__(self, api_url: str, headers: dict[str, str] | None = None):
        self.api_url = api_url
        self.headers = headers or {}

    def fetch_raw(self) -> list[dict[str, Any]]:
        r = requests.get(self.api_url, headers=self.headers, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"Vuln API failed ({r.status_code}): {r.text[:200]}")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError("Expected list of vuln records.")
        return data

    def fetch_vulns(self) -> list[Vulnerability]:
        return [Vulnerability(rec) for rec in self.fetch_raw()]
```

✅ **Checkpoint snippet** (students run this in a small test script or REPL):

```python
src = VulnerabilitySource(VULN_API_URL, headers=headers)
vulns = src.fetch_vulns()
print("Vulns:", len(vulns))
print(vulns[0])
```

---

## 3) Step: Attach vulnerabilities to assets (without changing Asset class much)

Because your `Asset` class doesn’t have a `vulnerabilities` field yet, we’ll attach them dynamically *or* use a wrapper.

### Option A (simplest): attach an attribute dynamically

In Python, you can do:

```python
asset.vulnerabilities = []
```

Create: **`vulnerability_attach.py`**

```python
from typing import Dict, List
from asset import Asset
from vulnerability import Vulnerability

def attach_vulnerabilities(assets: list[Asset], vulns: list[Vulnerability]) -> None:
    # 1) Create an index of vulns by hostname/ip
    vulns_by_host: Dict[str, List[Vulnerability]] = {}
    vulns_by_ip: Dict[str, List[Vulnerability]] = {}

    for v in vulns:
        if v.asset_hostname:
            vulns_by_host.setdefault(v.asset_hostname.lower(), []).append(v)
        if v.asset_ip:
            vulns_by_ip.setdefault(v.asset_ip, []).append(v)

    # 2) Attach to each asset (mutating the original objects in the list)
    for each_asset in assets:
        each_asset.vulnerabilities = []  # overwrite each run (or keep + extend if you prefer)

        if each_asset.hostname and each_asset.hostname.lower() in vulns_by_host:
            each_asset.vulnerabilities.extend(vulns_by_host[each_asset.hostname.lower()])

        if each_asset.ip_address and each_asset.ip_address in vulns_by_ip:
            # Add any IP-matched vulns that weren't already included by hostname
            existing = {vv.key() for vv in each_asset.vulnerabilities}
            for vv in vulns_by_ip[each_asset.ip_address]:
                if vv.key() not in existing:
                    each_asset.vulnerabilities.append(vv)
```

✅ **Checkpoint:**

```python
attach_vulnerabilities(mgr.assets, vulns)
for a in mgr.assets[:3]:
    print(a.hostname, "vulns:", len(getattr(a, "vulnerabilities", [])))
```

---

## 4) Step: Decide what vulnerabilities deserve tickets

Create: **`prioritization.py`**

```python
from asset import Asset
from vulnerability import Vulnerability

def should_ticket(asset: Asset, vuln: Vulnerability) -> bool:
    # Ignore closed / false positives if your dataset has status
    if (vuln.status or "").lower() in {"false_positive", "closed", "mitigated"}:
        return False

    # Derive severity from CVSS (v3-style ranges)
    try:
        score = float(vuln.cvss_score) if vuln.cvss_score is not None else None
    except (TypeError, ValueError):
        score = None

    if score is None:
        # If CVSS is missing/unparseable, don't auto-ticket by default
        # (You could choose to ticket if exploit_available/internet_exposed instead.)
        return False

    if score >= 9.0:
        sev = "critical"
    elif score >= 7.0:
        sev = "high"
    elif score >= 4.0:
        sev = "medium"
    else:
        sev = "low"

    # Ticket anything High/Critical
    if sev in {"critical", "high"}:
        return True

    # Escalate Medium if exploit available + prod
    if sev == "medium" and vuln.exploit_available and (asset.environment or "").lower() == "prod":
        return True

    return False
```

---

## 5) Step: Create a Trello card (ticket)

You can find docs on how to get these values for your Trello environment variables in [the trello docs of this repo](./docs/trello_setting_up_api_access.md).

### A) Minimal Trello client

Create: **`trello_client.py`**

```python
import os
import requests
from typing import Any

class TrelloClient:
    def __init__(self):
        self.key = os.environ.get("TRELLO_KEY")
        self.token = os.environ.get("TRELLO_TOKEN")
        self.list_id = os.environ.get("TRELLO_LIST_ID")

        if not self.key or not self.token or not self.list_id:
            raise RuntimeError("Missing Trello env vars: TRELLO_KEY, TRELLO_TOKEN, TRELLO_LIST_ID")

    def create_card(self, name: str, desc: str) -> dict[str, Any]:
        url = "https://api.trello.com/1/cards"
        params = {
            "key": self.key,
            "token": self.token,
            "idList": self.list_id,
            "name": name,
            "desc": desc,
        }
        r = requests.post(url, params=params, timeout=10)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"Trello create failed ({r.status_code}): {r.text[:200]}")
        return r.json()
```

### B) Ticket formatting helper

Create: **`ticket_builder.py`**

```python
from asset import Asset
from vulnerability import Vulnerability

def build_ticket(asset: Asset, vuln: Vulnerability) -> tuple[str, str]:
    title = f"[{vuln.severity.upper()}] {vuln.cve_id} on {asset.hostname}"

    desc_lines = [
        "## Asset",
        f"- Hostname: {asset.hostname}",
        f"- IP: {asset.ip_address or 'n/a'}",
        f"- OS: {asset.os or 'n/a'}",
        f"- Environment: {asset.environment or 'n/a'}",
        f"- Owner: {asset.owner_context or 'n/a'}",
        f"- Source: {asset.source}",
        "",
        "## Vulnerability",
        f"- CVE: {vuln.cve_id}",
        f"- Title: {vuln.title}",
        f"- Severity: {vuln.severity}",
        f"- CVSS: {vuln.cvss_score if vuln.cvss_score is not None else 'n/a'}",
        f"- Exploit available: {vuln.exploit_available}",
        f"- Status: {vuln.status}",
        "",
        "## Recommended Fix",
        vuln.recommended_fix or "n/a",
        "",
        "## Notes",
        "This ticket was generated by the Ironclad Unified Inventory CLI as a simulation of remediation workflow.",
    ]

    return title, "\n".join(desc_lines)
```

---

## 6) Step: Add a new CLI command to create Trello tickets

### A) Add new command function in your main file

Add imports near the top of `main.py`:

```python
from vulnerability_source import VulnerabilitySource
from vulnerability_attach import attach_vulnerabilities
from prioritization import should_ticket
from trello_client import TrelloClient
from ticket_builder import build_ticket

VULN_API_URL = "https://my.api.mockaroo.com/ironclad/vulns/findings.json"
```

Add a command handler:

```python
def cmd_ticket(args) -> None:
    mgr = build_manager()
    mgr.pull(args.source)

    vuln_src = VulnerabilitySource(VULN_API_URL, headers=headers)
    vulns = vuln_src.fetch_vulns()

    attach_vulnerabilities(mgr.assets, vulns)

    trello = TrelloClient()
    created = 0

    for asset in mgr.assets:
        asset_vulns = getattr(asset, "vulnerabilities", [])
        for v in asset_vulns:
            if should_ticket(asset, v):
                title, desc = build_ticket(asset, v)
                trello.create_card(name=title, desc=desc)
                created += 1

                if args.limit and created >= args.limit:
                    print(f"Created {created} cards (limit reached).")
                    return

    print(f"Created {created} Trello cards.")
```

### B) Register the command in `main()`

Add:

```python
p_ticket = sub.add_parser("ticket", help="Create Trello tickets for prioritized vulnerabilities")
p_ticket.add_argument("--source", choices=["netbox", "qualys", "crowdstrike", "all"], default="all")
p_ticket.add_argument("--limit", type=int, default=20, help="Max cards to create in one run")
p_ticket.set_defaults(func=cmd_ticket)
```

✅ **How students run it:**

```bash
python ironclad_inventory_cli.py ticket --source all --limit 10
```

---

## 7) Notes for Students (Important)

### A) Don’t spam Trello

Use `--limit` while testing.

### B) Expected outcomes

* Some vulnerabilities won’t match assets (that’s realistic)
* Some assets may have many vulnerabilities
* Your prioritization function controls ticket volume


## 8) Optional upgrade: prevent duplicate Trello cards (simple dedupe)

If you want a quick extension: keep a set of `(hostname,cve)` keys created in this run:

```python
seen = set()
...
key = (asset.hostname.lower(), v.cve_id)
if key in seen:
    continue
seen.add(key)
```

---

# 🧩 Part 2 — Required Deliverables

Students must submit:

* Updated CLI code
* Screenshot of Trello board showing generated cards
* Terminal output showing:

  * number of vulnerabilities
  * number of tickets created
* README explaining:

  * their prioritization logic
  * how they derived severity

---

# 🧠 Part 3 — Challenges (Choose 3)

## 🔹 Challenge 1 — Duplicate Prevention

Do not create a ticket if one already exists for the same `(hostname, cve_id)`.

Hint:

* Use Trello API to list cards first
* Or track created keys locally

---

## 🔹 Challenge 2 — SLA Enforcement

Add due dates:

* Critical → 7 days
* High → 14 days
* Medium → 30 days

Trello supports `due` parameter.

---

## 🔹 Challenge 3 — Label by Severity

Create labels in Trello for:

* Critical
* High
* Medium
* Low

Attach labels when creating card.

---

## 🔹 Challenge 4 — Owner-Based Assignment

If `asset.owner_context` exists:

* Map owner → Trello member
* Auto-assign the card

---

## 🔹 Challenge 5 — Metrics Dashboard Output

Print:

```
Tickets created: 12
Critical: 3
High: 6
Medium: 3
By Team:
  Finance: 4
  HR: 2
  IT: 6
```

---

## 🔹 Challenge 6 — Risk Escalation Rule

If:

* internet_exposed == True
  AND
* exploit_available == True

Then treat medium as high.

---

# 📊 Grading Rubric (100 pts)

| Category                     | Points |
| ---------------------------- | ------ |
| Vulnerability ingestion      | 15     |
| Correlation to assets        | 15     |
| Severity derivation          | 15     |
| Prioritization logic         | 15     |
| Trello integration works     | 20     |
| Code structure & cleanliness | 10     |
| Challenges (3 × 5 pts)       | 15     |

---

# 🧠 Why This Assignment Matters

This simulates:

* Vulnerability management workflows
* Security-to-operations handoffs
* Risk-based remediation
* API-driven automation
* SOC + DevOps collaboration

Students now move beyond “finding problems” into “operationalizing security.”
