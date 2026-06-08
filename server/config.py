"""
SafeVision System Configuration
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

#  MongoDB Configuration 
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME   = os.getenv("DB_NAME",   "safevision")

#  Server Network Configuration 
IP   = os.getenv("SERVER_IP",   "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "8080"))

#  Model & System Info 
MODEL_VERSION = "v15"
LOCATION      = "Security System"


