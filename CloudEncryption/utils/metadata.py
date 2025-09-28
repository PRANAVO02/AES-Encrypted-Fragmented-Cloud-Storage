import json
import os
from config import FRAGMENT_FOLDER

METADATA_FILE = os.path.join(FRAGMENT_FOLDER, "metadata.json")

def save_metadata(fragments_info):
    with open(METADATA_FILE, "w") as f:
        json.dump(fragments_info, f, indent=4)

def load_metadata():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as f:
            return json.load(f)
    return {}
