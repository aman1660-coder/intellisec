from __future__ import annotations

import json
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings


class JsonStorage:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

        if not self.path.exists():
            self._write({"users": [], "scans": []})

    def _read(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(
                self.path.read_text(encoding="utf-8")
            )

    def _write(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            self.path.write_text(
                json.dumps(
                    data,
                    indent=2,
                    sort_keys=True
                ),
                encoding="utf-8"
            )

    def create_user(
        self,
        user: dict[str, Any]
    ) -> dict[str, Any]:

        data = self._read()

        user = deepcopy(user)

        user["id"] = str(uuid.uuid4())

        user["created_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        data["users"].append(user)

        self._write(data)

        return user

    def get_user_by_email(
        self,
        email: str
    ) -> dict[str, Any] | None:

        data = self._read()

        email_norm = email.lower()

        for user in data["users"]:

            if user.get("email", "").lower() == email_norm:
                return deepcopy(user)

        return None

    def get_user(
        self,
        user_id: str
    ) -> dict[str, Any] | None:

        data = self._read()

        for user in data["users"]:

            if user.get("id") == user_id:
                return deepcopy(user)

        return None

    def add_scan(
        self,
        scan: dict[str, Any]
    ) -> dict[str, Any]:

        data = self._read()

        scan = deepcopy(scan)

        scan["id"] = (
            scan.get("id")
            or str(uuid.uuid4())
        )

        data["scans"].append(scan)

        self._write(data)

        return scan

    def list_scans(
        self,
        user_id: str
    ) -> list[dict[str, Any]]:

        data = self._read()

        scans = [
            deepcopy(scan)
            for scan in data["scans"]
            if scan.get("user_id") == user_id
        ]

        return sorted(
            scans,
            key=lambda item: item.get("timestamp", ""),
            reverse=True
        )

    def get_scan(
        self,
        user_id: str,
        scan_id: str
    ) -> dict[str, Any] | None:

        data = self._read()

        for scan in data["scans"]:

            if (
                scan.get("id") == scan_id
                and scan.get("user_id") == user_id
            ):
                return deepcopy(scan)

        return None


class MongoStorage:

    def __init__(
        self,
        uri: str,
        db_name: str
    ):

        from pymongo import MongoClient

        self.client = MongoClient(
            uri,
            serverSelectionTimeoutMS=5000
        )

        self.db = self.client[db_name]

        # Actually verify MongoDB connection
        self.client.admin.command("ping")

        print(
            f"Successfully connected to MongoDB database: {db_name}"
        )

    def create_user(
        self,
        user: dict[str, Any]
    ) -> dict[str, Any]:

        user = deepcopy(user)

        user["id"] = str(uuid.uuid4())

        user["created_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        # Important:
        # insert a copy so MongoDB does not add
        # ObjectId to the dictionary returned by API
        self.db.users.insert_one(
            deepcopy(user)
        )

        return user

    def get_user_by_email(
        self,
        email: str
    ) -> dict[str, Any] | None:

        return self.db.users.find_one(
            {
                "email": email.lower()
            },
            {
                "_id": 0
            }
        )

    def get_user(
        self,
        user_id: str
    ) -> dict[str, Any] | None:

        return self.db.users.find_one(
            {
                "id": user_id
            },
            {
                "_id": 0
            }
        )

    def add_scan(
        self,
        scan: dict[str, Any]
    ) -> dict[str, Any]:

        scan = deepcopy(scan)

        scan["id"] = (
            scan.get("id")
            or str(uuid.uuid4())
        )

        # IMPORTANT FIX:
        # PyMongo adds _id ObjectId to the dictionary
        # passed to insert_one().
        #
        # Therefore insert a separate deepcopy.
        self.db.scans.insert_one(
            deepcopy(scan)
        )

        # The returned scan contains no MongoDB ObjectId,
        # so FastAPI/Pydantic can serialize it safely.
        return scan

    def list_scans(
        self,
        user_id: str
    ) -> list[dict[str, Any]]:

        return list(
            self.db.scans.find(
                {
                    "user_id": user_id
                },
                {
                    "_id": 0
                }
            ).sort(
                "timestamp",
                -1
            )
        )

    def get_scan(
        self,
        user_id: str,
        scan_id: str
    ) -> dict[str, Any] | None:

        return self.db.scans.find_one(
            {
                "id": scan_id,
                "user_id": user_id
            },
            {
                "_id": 0
            }
        )


def build_storage() -> JsonStorage | MongoStorage:

    if settings.mongodb_uri:

        try:

            mongo_storage = MongoStorage(
                settings.mongodb_uri,
                settings.mongodb_db
            )

            print(
                f"Using MongoDB storage: "
                f"{settings.mongodb_db}"
            )

            return mongo_storage

        except Exception as error:

            print(
                f"MongoDB connection failed: {error}"
            )

            print(
                "Falling back to JSON storage"
            )

            return JsonStorage(
                settings.data_dir / "intellisec.json"
            )

    print(
        "MONGODB_URI is not configured. "
        "Using JSON storage."
    )

    return JsonStorage(
        settings.data_dir / "intellisec.json"
    )


storage = build_storage()