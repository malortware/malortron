import os
from pymongo import MongoClient

discord_token = os.environ.get("DISCORD_TOKEN")
mongodb_connection = os.environ.get("MONGODB_URI", "mongodb://localhost/ctfteams")
maintainer_id = os.environ.get("MAINTAINER_ID")
github_repo = os.environ.get("GITHUB_REPO", "https://github.com/NullPxl/NullCTF")
