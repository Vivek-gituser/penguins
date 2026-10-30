from database.supabase_client import get_supabase_client

try:
    client = get_supabase_client()
    result = client.table("agents").select("id").limit(1).execute()
    print("SUPABASE CONNECTION SUCCESSFUL")
    print("Agents table is reachable.")
except Exception as error:
    print("SUPABASE CONNECTION FAILED")
    print(type(error).__name__ + ":", str(error))
