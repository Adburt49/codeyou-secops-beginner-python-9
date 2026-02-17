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
