"""Historique de captures persistant dans Supabase/Postgres."""

from __future__ import annotations

from typing import Any, Iterator

from supabase import Client, create_client


class SupabaseHistoryStore:
    """Même contrat que HistoryStore, avec écritures serveur privées."""

    def __init__(self, url: str, service_role_key: str) -> None:
        if not url or not service_role_key:
            raise ValueError("La configuration Supabase est incomplète.")
        self._client: Client = create_client(url, service_role_key)

    def recover_interrupted_sessions(self) -> int:
        response = (
            self._client.table("capture_sessions")
            .update({"status": "INTERRUPTED", "ended_at": _now_iso()})
            .eq("status", "RUNNING")
            .select("id")
            .execute()
        )
        return len(response.data or [])

    def create_session(
        self,
        interface_id: str,
        interface_name: str,
        started_at: str,
    ) -> int:
        response = (
            self._client.table("capture_sessions")
            .insert({
                "interface_id": interface_id,
                "interface_name": interface_name,
                "status": "RUNNING",
                "packet_count": 0,
                "bytes_captured": 0,
                "started_at": started_at,
            })
            .execute()
        )
        if not response.data:
            raise RuntimeError("Supabase n'a pas renvoyé l'identifiant de session.")
        return int(response.data[0]["id"])

    def finish_session(
        self,
        session_id: int,
        status: str,
        ended_at: str,
        packet_count: int,
        bytes_captured: int,
    ) -> None:
        response = (
            self._client.table("capture_sessions")
            .update({
                "status": status,
                "ended_at": ended_at,
                "packet_count": max(0, int(packet_count)),
                "bytes_captured": max(0, int(bytes_captured)),
            })
            .eq("id", session_id)
            .select("id")
            .execute()
        )
        if not response.data:
            raise KeyError(f"Session inconnue : {session_id}")

    def save_packet_summaries(
        self,
        session_id: int,
        packets: list[tuple[int, dict[str, Any]]],
    ) -> None:
        if not packets:
            return
        records = [
            {
                "session_id": session_id,
                "packet_index": index,
                "packet_summary": packet,
            }
            for index, packet in packets
        ]
        self._client.table("packet_summaries").upsert(
            records,
            on_conflict="session_id,packet_index",
        ).execute()

    def has_session(self, session_id: int) -> bool:
        response = (
            self._client.table("capture_sessions")
            .select("id")
            .eq("id", session_id)
            .limit(1)
            .execute()
        )
        return bool(response.data)

    def iter_packet_summaries(
        self,
        session_id: int,
        batch_size: int = 500,
    ) -> Iterator[dict[str, Any]]:
        page_size = max(1, min(int(batch_size), 1000))
        offset = 0
        while True:
            response = (
                self._client.table("packet_summaries")
                .select("packet_summary")
                .eq("session_id", session_id)
                .order("packet_index")
                .range(offset, offset + page_size - 1)
                .execute()
            )
            rows = response.data or []
            for row in rows:
                yield row["packet_summary"]
            if len(rows) < page_size:
                break
            offset += page_size

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        response = (
            self._client.table("capture_sessions")
            .select(
                "id,interface_id,interface_name,status,packet_count,"
                "bytes_captured,started_at,ended_at"
            )
            .order("id", desc=True)
            .limit(safe_limit)
            .execute()
        )
        return list(response.data or [])


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
