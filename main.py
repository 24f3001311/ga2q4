from fastapi import FastAPI, Response
from pydantic import BaseModel
import jwt

app = FastAPI()

# Assigned Public Key
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# Assigned Constraints[cite: 8]
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-ynlt4s6l.apps.exam.local"

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(request: TokenRequest, response: Response):
    try:
        # PyJWT automatically validates the RS256 signature, expiry time, issuer, and audience[cite: 8]
        decoded = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE
        )
        
        # Valid Token: Return 200 with extracted claims[cite: 8]
        return {
            "valid": True,
            "email": decoded.get("email"),
            "sub": decoded.get("sub"),
            "aud": decoded.get("aud")
        }
        
    except jwt.PyJWTError:
        # Invalid Token (tampered, expired, wrong aud/iss): Return 401[cite: 8]
        response.status_code = 401
        return {"valid": False}