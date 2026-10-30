import os

from dotenv import load_dotenv
from supabase import create_client

from database.supabase_repository import SupabaseRepository

load_dotenv()


def _auth_client():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_ANON_KEY")

    if not url or not key:
        raise RuntimeError("Supabase URL or publishable key is missing.")

    return create_client(url, key)


def is_active_reviewer(user_id):
    if not isinstance(user_id, str) or not user_id.strip():
        return False

    response = (
        SupabaseRepository().client.table("reviewers")
        .select("active")
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )

    return bool(response.data and response.data.get("active") is True)


def _session_data(client, user, session):
    if not user or not session:
        raise RuntimeError("Supabase did not return a valid session.")

    if not is_active_reviewer(user.id):
        raise PermissionError("This account is not an active AGENTGATE reviewer.")

    return {
        "user_id": user.id,
        "email": user.email,
        "access_token": session.access_token,
        "refresh_token": session.refresh_token,
    }


def sign_in_reviewer(email, password):
    if not isinstance(email, str) or not email.strip():
        raise ValueError("Enter your reviewer email.")

    if not isinstance(password, str) or not password:
        raise ValueError("Enter your password.")

    client = _auth_client()
    response = client.auth.sign_in_with_password({
        "email": email.strip(),
        "password": password,
    })

    return _session_data(client, response.user, response.session)


def restore_reviewer_session(access_token, refresh_token):
    if not access_token or not refresh_token:
        raise ValueError("Reviewer session is missing.")

    client = _auth_client()
    client.auth.set_session(access_token, refresh_token)

    user_response = client.auth.get_user()
    session = client.auth.get_session()

    return _session_data(client, user_response.user, session)
