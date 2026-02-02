from typing import Any
from asset import Asset
import requests
import os

class InventorySource:
    name: str = "base"

    def __init__(self, api_url: str):
        self.api_url = api_url

    def fetch_raw(self):
        headers = {
            "X-API-Key": os.environ.get("IRONCLAD_API_KEY")
        }
        r = requests.get(self.api_url, headers=headers, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"{self.name} fetch failed ({r.status_code}): {r.text[:200]}")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"{self.name} returned unexpected JSON (expected list).")
        return data

    def normalize(self, record: dict[str, Any]) -> Asset:
        raise NotImplementedError
    
    def fetch_assets(self) -> list[Asset]:
        raw = self.fetch_raw()
        results = []
        for each_record in raw:
            results.append(self.normalize(each_record))

        return results
    
class NetboxInventorySource(InventorySource):
    name = "netbox"

    def normalize(self, record: dict[str, Any]) -> Asset:
        return Asset(
            asset_id=record["id"],
            hostname=record["device_name"],
            ip_address=record["primary_ip"],
            os=record["platform"],
            environment=record["environment"],
            owner_context=record["tenant"],
            source=self.name,
            raw=record
        )
    
class QualysInventorySource(InventorySource):
    name = "qualys"

    def normalize(self, record: dict[str, Any]) -> Asset:
        return Asset(
            asset_id=record["asset_id"],
            hostname=record["hostname"],
            ip_address=record["ip_address"],
            os=record["operating_system"],
            environment=record["asset_group"],
            owner_context="Not available",
            source=self.name,
            raw=record
        )
    
class CrowdstrikeInventorySource(InventorySource):
    name = "crowdstrike"

    def normalize(self, record: dict[str, Any]) -> Asset:
        return Asset(
            asset_id=record["sensor_id"],
            hostname=record["hostname"],
            ip_address=record["local_ip"],
            os=record["os_version"],
            environment=record["device_type"],
            owner_context="Not available",
            source=self.name,
            raw=record
        )