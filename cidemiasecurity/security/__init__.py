from fastapi.security import OAuth2PasswordBearer
from cidemiasecurity.config.loader import get_config

AUTH_URL = get_config("AUTH_URL", None) or get_config("CIDEMIA_AUTH_URL", None)
TOKEN_URL = "/api/auth/token"
if AUTH_URL:
    TOKEN_URL = AUTH_URL + TOKEN_URL

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL)
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL, auto_error=False)
