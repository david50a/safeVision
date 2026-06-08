"""
SafeVision Guard Manager
=========================
CRUD for guards, zones, and guard-zone assignments.
Guards are stored in MongoDB `guards` collection.
Zones are stored in MongoDB `zones` collection.

A Zone groups one or more cameras into a logical area (e.g. "Lobby", "Parking").
Guards are assigned to zones. When an alarm fires for a camera, the engine
looks up which zone owns that camera, then SMS every guard assigned to that zone.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Optional

from storage import JsonCollection

logger = logging.getLogger(__name__)

#   File-based Storage                            ─
_GUARDS_COL = JsonCollection("database/guards.jsonl")
_ZONES_COL  = JsonCollection("database/zones.jsonl")




#  GUARD  CRUD

class GuardManager:

    #   Guards                                 

    @staticmethod
    def create_guard(
        name:     str,
        phone:    str,
        email:    str = "",
        badge_id: str = "",
        notes:    str = "",
    ) -> dict:
        """Create a new guard. Returns the created document."""
        guard = {
            "guard_id":  uuid.uuid4().hex,
            "name":      name.strip(),
            "phone":     phone.strip(),
            "email":     email.strip(),
            "badge_id":  badge_id.strip(),
            "notes":     notes.strip(),
            "active":    True,
            "zones":     [],          # list of zone_ids
            "created_at": datetime.datetime.utcnow(),
        }
        _GUARDS_COL.insert_one(guard)
        guard.pop("_id", None)
        logger.info(f"[GUARD] Created guard: {name} ({guard['guard_id']})")
        return guard

    @staticmethod
    def update_guard(guard_id: str, updates: dict) -> bool:
        allowed = {"name", "phone", "email", "badge_id", "notes", "active"}
        safe = {k: v for k, v in updates.items() if k in allowed}
        if not safe:
            return False
        result = _GUARDS_COL.update_one({"guard_id": guard_id}, {"$set": safe})
        return result.modified_count > 0

    @staticmethod
    def delete_guard(guard_id: str) -> bool:
        result = _GUARDS_COL.delete_one({"guard_id": guard_id})
        if result.deleted_count:
            logger.info(f"[GUARD] Deleted guard {guard_id}")
        return result.deleted_count > 0

    @staticmethod
    def get_guard(guard_id: str) -> Optional[dict]:
        doc = _GUARDS_COL.find_one({"guard_id": guard_id}, {"_id": 0})
        return doc

    @staticmethod
    def list_guards(active_only: bool = False) -> list[dict]:
        query = {"active": True} if active_only else {}
        return list(_GUARDS_COL.find(query, {"_id": 0}).sort("name", 1))

    #   Zone Assignments                           ─

    @staticmethod
    def assign_to_zone(guard_id: str, zone_id: str) -> bool:
        """Add zone_id to guard's zone list (idempotent)."""
        result = _GUARDS_COL.update_one(
            {"guard_id": guard_id},
            {"$addToSet": {"zones": zone_id}},
        )
        return result.matched_count > 0

    @staticmethod
    def remove_from_zone(guard_id: str, zone_id: str) -> bool:
        """Remove zone_id from guard's zone list."""
        result = _GUARDS_COL.update_one(
            {"guard_id": guard_id},
            {"$pull": {"zones": zone_id}},
        )
        return result.matched_count > 0

    #   Zone lookup (used by AlarmEngine)                   

    @staticmethod
    def get_guards_for_camera(camera_id: str) -> list[dict]:
        """
        Return all active guards assigned to any zone that contains camera_id.
        Called by AlarmEngine._send_sms() to find who to notify.
        """
        zone_docs = list(_ZONES_COL.find({"cameras": camera_id}, {"zone_id": 1}))
        zone_ids  = [z["zone_id"] for z in zone_docs]
        if not zone_ids:
            return []
        guards = list(_GUARDS_COL.find(
            {"active": True, "zones": {"$in": zone_ids}},
            {"_id": 0},
        ))
        # Deduplicate by guard_id (guard may cover multiple matching zones)
        seen: set[str] = set()
        result = []
        for g in guards:
            if g["guard_id"] not in seen:
                seen.add(g["guard_id"])
                result.append(g)
        return result

#  ZONE  CRUD

class ZoneManager:

    @staticmethod
    def create_zone(
        name:        str,
        cameras:     list[str] = None,
        description: str = "",
    ) -> dict:
        zone = {
            "zone_id":     uuid.uuid4().hex,
            "name":        name.strip(),
            "cameras":     cameras or [],
            "description": description.strip(),
            "created_at":  datetime.datetime.utcnow(),
        }
        _ZONES_COL.insert_one(zone)
        zone.pop("_id", None)
        logger.info(f"[ZONE] Created zone: {name} ({zone['zone_id']})")
        return zone

    @staticmethod
    def update_zone(zone_id: str, updates: dict) -> bool:
        allowed = {"name", "cameras", "description"}
        safe = {k: v for k, v in updates.items() if k in allowed}
        if not safe:
            return False
        result = _ZONES_COL.update_one({"zone_id": zone_id}, {"$set": safe})
        return result.modified_count > 0

    @staticmethod
    def delete_zone(zone_id: str) -> bool:
        result = _ZONES_COL.delete_one({"zone_id": zone_id})
        if result.deleted_count:
            # Remove zone from all guards
            _GUARDS_COL.update_many({}, {"$pull": {"zones": zone_id}})
            logger.info(f"[ZONE] Deleted zone {zone_id}")
        return result.deleted_count > 0

    @staticmethod
    def get_zone(zone_id: str) -> Optional[dict]:
        return _ZONES_COL.find_one({"zone_id": zone_id}, {"_id": 0})

    @staticmethod
    def list_zones() -> list[dict]:
        return list(_ZONES_COL.find({}, {"_id": 0}).sort("name", 1))

    @staticmethod
    def add_camera(zone_id: str, camera_id: str) -> bool:
        result = _ZONES_COL.update_one(
            {"zone_id": zone_id},
            {"$addToSet": {"cameras": camera_id}},
        )
        return result.matched_count > 0

    @staticmethod
    def remove_camera(zone_id: str, camera_id: str) -> bool:
        result = _ZONES_COL.update_one(
            {"zone_id": zone_id},
            {"$pull": {"cameras": camera_id}},
        )
        return result.matched_count > 0
