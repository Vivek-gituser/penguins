import os
from functools import lru_cache

from dotenv import load_dotenv
from supabase import Client, create_client


load_dotenv()


@lru_cache(maxsize=1)
def get_supabase_client() -> Client:
    """Return the trusted backend Supabase client."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        raise RuntimeError(
            "SUPABASE_URL or SUPABASE_KEY missing from .env"
        )

    if "your-project-id" in url or "your-secret-key" in key:
        raise RuntimeError("Replace placeholder values in .env")

    return create_client(url, key)
