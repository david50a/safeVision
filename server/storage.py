import os
import threading
import datetime
import logging
from typing import Optional, List, Dict, Any, Union
from pymongo import MongoClient
import config

logger = logging.getLogger(__name__)

class MongoStorage:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MongoStorage, cls).__new__(cls)
                cls._instance._init_client()
            return cls._instance

    def _init_client(self):
        try:
            self.client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
            self.db = self.client[config.DB_NAME]
            # Verify connection
            self.client.server_info()
            logger.info(f"Connected to MongoDB at {config.MONGO_URI}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            # Fallback or raising error depending on system requirements
            # For now, we allow the app to crash or handle it gracefully if needed
            raise

    def get_collection(self, name: str):
        return self.db[name]

def get_collection(name: str):
    """Utility to get a collection, stripping .jsonl if present for transition."""
    coll_name = name.split('/')[-1].replace('.jsonl', '')
    return MongoStorage().get_collection(coll_name)

#   Compatibility Layer                            
class JsonCollection:
    """
    A wrapper around pymongo.Collection that maintains the interface 
    previously provided by the JSONL implementation.
    """
    def __init__(self, name: str):
        self._coll = get_collection(name)

    def insert_one(self, doc: Dict):
        return self._coll.insert_one(doc)

    def find(self, query: Dict = {}, projection: Dict = {}):
        return self._coll.find(query, projection)

    def find_one(self, query: Dict, projection: Dict = {}):
        return self._coll.find_one(query, projection)

    def update_one(self, query: Dict, update: Dict):
        return self._coll.update_one(query, update)

    def update_many(self, query: Dict, update: Dict):
        return self._coll.update_many(query, update)

    def delete_one(self, query: Dict):
        return self._coll.delete_one(query)

    def delete_many(self, query: Dict):
        return self._coll.delete_many(query)

    def aggregate(self, pipeline: List[Dict]):
        return self._coll.aggregate(pipeline)

    def create_index(self, *args, **kwargs):
        return self._coll.create_index(*args, **kwargs)
