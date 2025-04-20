import os
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from keycloak import KeycloakOpenID
from jwcrypto import jwk 
from fastapi.responses import JSONResponse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "reports-realm")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "reports-api")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "oNwoLQdvJAvRcL89SydqCWCe5ry1jMgq")

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    realm_name=KEYCLOAK_REALM_NAME,
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret_key=KEYCLOAK_CLIENT_SECRET
)

p_jwk = None

def public_key(pkey: str) -> str:
    lkey = pkey.strip()
    line = [lkey[i:i+64] for i in range(0, len(lkey), 64)]
    pkey = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(line) + "\n-----END PUBLIC KEY-----"
    return pkey

def verify_token(authorization: str = Header(None)):
   
    token = authorization.split("Bearer ")[1]

    global p_jwk
    try:
        if p_jwk is None:
            rp_key = keycloak_openid.public_key()
            fp_key = public_key(rp_key)
            o_jwk = jwk.JWK.from_pem(fp_key.encode("utf-8"))
            p_jwk = o_jwk
        user_info = keycloak_openid.decode_token(token, key=p_jwk)
        return user_info
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/reports")
async def get_reports(user: dict = Depends(verify_token)):
    roles = user.get("realm_access", {}).get("roles", [])
    users = user.get("sub")

    if "prothetic_user" not in roles:
        raise HTTPException(status_code=401, detail="Invalid role")

    return JSONResponse(content={"user_id": users, "roles": roles})
