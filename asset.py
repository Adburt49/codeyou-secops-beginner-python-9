from typing import Optional, Any

class Asset:
    asset_id: str
    hostname: str
    ip_address: Optional[str]
    os: Optional[str]
    environment: Optional[str]
    owner_context: Optional[str]
    source: str
    raw: dict[str, Any]

    def __init__(self, *args, **kwargs):
        self.asset_id = kwargs.get("asset_id")
        self.hostname = kwargs.get("hostname", "")
        self.ip_address = kwargs.get("ip_address")
        self.os = kwargs.get("os")
        self.environment = kwargs.get("environmnet")
        self.owner_context = kwargs.get("owner_context")
        self.source = kwargs.get("source", "")
        self.raw = kwargs.get("raw", {})

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
    
    def __str__(self):
        return self.summary()