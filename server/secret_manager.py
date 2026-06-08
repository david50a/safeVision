import json
import os
from pathlib import Path
from typing import Optional, Any
from model.model_protection import FileEncryptor

class SecretManager:
    """
    A local-first encrypted secret store.
    Protects sensitive keys (API tokens, passwords) using the master key.
    """
    def __init__(self, storage_path: str = "database/secrets.enc"):
        self.storage_path = Path(storage_path)
        self.encryptor = FileEncryptor()
        self._secrets: dict[str, Any] = {}
        self._is_unlocked = False

    def unlock(self, password: str) -> bool:
        """Decrypt and load secrets into memory."""
        if not self.storage_path.exists():
            # First run: initialize empty store
            self._secrets = {}
            self._is_unlocked = True
            return True

        # Temporary file for decryption
        temp_dec = self.storage_path.with_suffix(".tmp.json")
        try:
            if self.encryptor.decrypt_file(str(self.storage_path), str(temp_dec), password):
                with open(temp_dec, "r") as f:
                    self._secrets = json.load(f)
                self._is_unlocked = True
                return True
        except Exception:
            pass
        finally:
            if temp_dec.exists():
                os.remove(temp_dec)
        
        return False

    def save(self, password: str) -> bool:
        """Encrypt and save the current secret store to disk."""
        if not self._is_unlocked:
            return False

        temp_json = self.storage_path.with_suffix(".json")
        try:
            # Ensure parent directory exists
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(temp_json, "w") as f:
                json.dump(self._secrets, f, indent=4)
            
            self.encryptor.encrypt_file(str(temp_json), str(self.storage_path), password)
            return True
        finally:
            if temp_json.exists():
                os.remove(temp_json)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a secret."""
        if not self._is_unlocked:
            raise RuntimeError("SecretManager is locked. Call unlock() first.")
        return self._secrets.get(key, default)

    def set(self, key: str, value: Any):
        """Set a secret (requires save() to persist)."""
        if not self._is_unlocked:
            raise RuntimeError("SecretManager is locked. Call unlock() first.")
        self._secrets[key] = value

    def list_keys(self) -> list[str]:
        """Return list of available secret keys."""
        return list(self._secrets.keys())

# Global singleton instance
secrets = SecretManager()
