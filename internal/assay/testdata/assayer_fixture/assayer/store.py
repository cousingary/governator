"""Supabase-backed store for assayer traces and quarantine rows.

`supabase` is imported lazily (inside the client property) because it is
not installed in every environment that imports this module (e.g. local
dev), but is present on the deployment target.
"""

import json
import os


class Store:
    def __init__(self, url=None, key=None, fallback_path=None):
        self.url = url or os.environ.get("SUPABASE_URL")
        self.key = key or os.environ.get("SUPABASE_SERVICE_KEY")
        self.fallback_path = fallback_path or os.environ.get(
            "ASSAYER_FALLBACK", "/opt/assayer/assayer_fallback.jsonl"
        )
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from supabase import create_client

            self._client = create_client(self.url, self.key)
        return self._client

    def insert_trace(self, row):
        return self.client.table("assayer_traces").insert(row).execute()

    def insert_quarantine(self, row) -> int:
        result = self.client.table("assayer_quarantine").insert(row).execute()
        return result.data[0]["id"]

    def seen_pass(self, pipeline, item_hash) -> bool:
        result = (
            self.client.table("assayer_traces")
            .select("id")
            .eq("pipeline", pipeline)
            .eq("item_hash", item_hash)
            .eq("verdict", "pass")
            .limit(1)
            .execute()
        )
        return bool(result.data)

    def list_quarantine(self, pipeline=None, since_iso=None, status="open"):
        query = self.client.table("assayer_quarantine").select("*")
        if pipeline:
            query = query.eq("pipeline", pipeline)
        if since_iso:
            query = query.gte("ts", since_iso)
        if status:
            query = query.eq("status", status)
        result = query.execute()
        return result.data

    def get_quarantine(self, qid):
        result = (
            self.client.table("assayer_quarantine")
            .select("*")
            .eq("id", qid)
            .limit(1)
            .execute()
        )
        return result.data[0] if result.data else None

    def set_quarantine_status(self, qid, status):
        result = (
            self.client.table("assayer_quarantine")
            .update({"status": status})
            .eq("id", qid)
            .execute()
        )
        return result.data

    def stats(self, since_iso=None):
        query = self.client.table("assayer_traces").select(
            "id,pipeline,verdict,checks_json,model,ts"
        )
        if since_iso:
            query = query.gte("ts", since_iso)
        result = query.execute()
        return result.data

    def fallback(self, row):
        try:
            path = self.fallback_path
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            table_hint = "assayer_quarantine" if "payload_json" in row else "assayer_traces"
            with open(path, "a") as f:
                f.write(
                    json.dumps({"table_hint": table_hint, "row": row}, default=str) + "\n"
                )
        except Exception:
            pass
