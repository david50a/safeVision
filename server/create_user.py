import sys
import getpass
from model.model_protection import RBACManager, AuditLogger

def main():
    username = "guard"
    role = "viewer"
    
    print(f"Creating user: '{username}' with role: '{role}'")
    
    # Resolve paths relative to this script's directory (which is 'server')
    import os
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "rbac_db.json")
    audit_path = os.path.join(base_dir, "server_audit.jsonl")
    
    # Initialize RBAC with the correct database path
    audit_log = AuditLogger(audit_path)
    rbac = RBACManager(db_path, audit_log)
    
    while True:
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        if not password:
            print("Password cannot be empty.")
            continue
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        break
        
    try:
        rbac.create_user(username, password, role, actor="admin")
        print("User created successfully!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
