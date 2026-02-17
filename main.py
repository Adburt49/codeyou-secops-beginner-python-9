import requests
import os
from typing import Any
from inventory_source import NetboxInventorySource, QualysInventorySource, CrowdstrikeInventorySource
from inventory_manager import InventoryManager
import argparse
from vulnerability_source import VulnerabilitySource
from vulnerability_attach import attach_vulnerabilities
from prioritization import should_ticket
from trello_client import TrelloClient
from ticket_builder import build_ticket

NETBOX_API_URL = "https://my.api.mockaroo.com/ironclad/netbox/inventory.json"
QUALYS_API_URL = "https://my.api.mockaroo.com/ironclad/qualys/inventory.json"
CROWDSTRIKE_API_URL = "https://my.api.mockaroo.com/ironclad/crowdstrike/inventory.json"
VULN_API_URL = "https://my.api.mockaroo.com/ironclad/vulns/findings.json"

headers = {
    "X-API-Key": os.environ.get("IRONCLAD_API_KEY")
}

def build_manager() -> InventoryManager:
    sources = {
        "netbox": NetboxInventorySource(NETBOX_API_URL),
        "qualys": QualysInventorySource(QUALYS_API_URL),
        "crowdstrike": CrowdstrikeInventorySource(CROWDSTRIKE_API_URL),
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


def main():
    p = argparse.ArgumentParser(prog="ironclad-inventory", description="Ironclad Unified Inventory CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pull = sub.add_parser("pull", help="Pull inventory from a source")
    p_pull.add_argument("--source", choices=["netbox", "qualys", "crowdstrike", "all"], default="all")
    p_pull.set_defaults(func=cmd_pull)

    p_list = sub.add_parser("list", help="List assets")
    p_list.add_argument("--source", choices=["netbox", "qualys", "crowdstrike", "all"], default="all")
    p_list.set_defaults(func=cmd_list)

    p_search = sub.add_parser("search", help="Search assets by keyword")
    p_search.add_argument("--source", choices=["netbox", "qualys", "crowdstrike", "all"], default="all")
    p_search.add_argument("--query", required=True)
    p_search.add_argument("--limit", type=int, default=150)
    p_search.set_defaults(func=cmd_search)

    p_stats = sub.add_parser("stats", help="Show counts by source")
    p_stats.add_argument("--source", choices=["netbox", "qualys", "crowdstrike", "all"], default="all")
    p_stats.set_defaults(func=cmd_stats)

    p_ticket = sub.add_parser("ticket", help="Create Trello tickets for prioritized vulnerabilities")
    p_ticket.add_argument("--source", choices=["netbox", "qualys", "crowdstrike", "all"], default="all")
    p_ticket.add_argument("--limit", type=int, default=20, help="Max cards to create in one run")
    p_ticket.set_defaults(func=cmd_ticket)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()