from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
from collections import OrderedDict

logger = logging.getLogger(__name__)


class SessionMemoryStore:
    def __init__(self, max_sessions: int = 100, max_messages_per_session: int = 20):
        self.max_sessions = max_sessions
        self.max_messages_per_session = max_messages_per_session
        self._sessions: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def get_session(self, session_id: str) -> Dict[str, Any]:
        if session_id not in self._sessions:
            logger.info(f"Creating new session: {session_id}")
            self._sessions[session_id] = {
                "session_id": session_id,
                "messages": [],
                "context": {},
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "message_count": 0,
            }
            if len(self._sessions) > self.max_sessions:
                oldest = next(iter(self._sessions))
                logger.info(f"Evicting oldest session: {oldest}")
                del self._sessions[oldest]

        self._sessions.move_to_end(session_id)
        return self._sessions[session_id]

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        session = self.get_session(session_id)

        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }

        session["messages"].append(message)
        session["message_count"] += 1
        session["updated_at"] = datetime.now().isoformat()

        if len(session["messages"]) > self.max_messages_per_session:
            removed = session["messages"].pop(0)
            logger.debug(
                f"Removed old message from session {session_id}: "
                f"{removed['content'][:50]}..."
            )

    def get_messages(
        self,
        session_id: str,
        limit: Optional[int] = None
    ) -> List[Dict[str, str]]:
        session = self.get_session(session_id)
        messages = session["messages"]

        if limit is not None and limit > 0:
            messages = messages[-limit:]
        return [
            {"role": msg["role"], "content": msg["content"]}
            for msg in messages
        ]

    def update_context(
        self,
        session_id: str,
        context: Dict[str, Any]
    ) -> None:
        session = self.get_session(session_id)
        session["context"].update(context)
        session["updated_at"] = datetime.now().isoformat()

    def get_context(self, session_id: str) -> Dict[str, Any]:

        session = self.get_session(session_id)
        return session["context"]

    def clear_session(self, session_id: str) -> bool:

        if session_id in self._sessions:
            logger.info(f"Clearing session: {session_id}")
            del self._sessions[session_id]
            return True
        return False

    def list_sessions(self) -> List[str]:
        return list(self._sessions.keys())

    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        session = self.get_session(session_id)
        return {
            "session_id": session["session_id"],
            "created_at": session["created_at"],
            "updated_at": session["updated_at"],
            "message_count": session["message_count"],
            "context_keys": list(session["context"].keys()),
        }



_memory_store: Optional[SessionMemoryStore] = None


def get_memory_store() -> SessionMemoryStore:
    global _memory_store
    if _memory_store is None:
        _memory_store = SessionMemoryStore()
    return _memory_store
