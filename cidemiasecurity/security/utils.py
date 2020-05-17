from datetime import datetime, timedelta
from typing import List, Optional, Union, Callable

import jwt
from fastapi import Depends, HTTPException
from passlib.context import CryptContext
from jwt import PyJWTError
from starlette.status import HTTP_401_UNAUTHORIZED

from cidemiasecurity.config.loader import get_config
from cidemiasecurity.crypto.hash_utils import hash_token
from cidemiasecurity.security import oauth2_scheme, optional_oauth2_scheme
from cidemiasecurity.security.models import UserModel, RefreshTokenInfo

default_jwt_secret_key = None
JWT_SECRET_KEY = None
ALGORITHM = None
ACCESS_TOKEN_EXPIRE_MINUTES: int = None
_CONFIG_LOADED = False


def load_all_config():
    """
    This method will ensure that all config are load
    :return:
    """
    global _CONFIG_LOADED
    if _CONFIG_LOADED is False:
        global JWT_SECRET_KEY
        global ALGORITHM
        global ACCESS_TOKEN_EXPIRE_MINUTES

        JWT_SECRET_KEY = get_config("JWT_SECRET_KEY", default_jwt_secret_key)
        ALGORITHM = get_config("JWT_ALGORITHM", "HS256")
        ACCESS_TOKEN_EXPIRE_MINUTES = int(get_config("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30))
        _CONFIG_LOADED = True


def get_password_context(context_name: str) -> CryptContext:
    """
    Get a password context
    :param context_name: str -> The name of the context
    :return: CryptContext
    """
    return CryptContext(schemes=[context_name], deprecated="auto")


default_pwd_context = get_password_context("bcrypt")  # Set Bcrypt as default hashing algorithm


def password_verifier(context: Union[str, CryptContext]) -> Callable[[str, str], bool]:
    """
    A method to generate a password verifier based on a password context
    :param context: Union[str, CryptContext] -> The context
    :return: Callable[[str, str], bool] -> The verifier function
    """
    if isinstance(context, str):
        context = get_password_context(context)

    def verifier(plain_password: str, hashed_password: str) -> bool:
        """
        This will verify a password by using the hashing algorithm {str(context)}
        :param plain_password: str -> The plain text password
        :param hashed_password: str -> The hashed password
        :return: bool -> Tells if plain matches the hashed password
        """
        return context.verify(plain_password, hashed_password)
    return verifier


def verify_password_with_context(plain_password: str, hashed_password: str, context: CryptContext) -> bool:
    """
    This will verify a password by using a given algorithm
    :param plain_password: str -> The plain text password
    :param hashed_password: str -> The hashed password
    :param context: CryptoContext -> The context to use
    :return: bool -> Tells if plain matches the hashed password
    """
    return context.verify(plain_password, hashed_password)


def get_password_hash_with_context(password, context: CryptContext) -> str:
    """
    Hash a password by using a given algorithm
    :param password: str -> The plain text password
    :param context: CryptContext -> the context to use to generate hash of the password
    :return: str -> The hashed password
    """
    return context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    This will verify a password by using the default hashing algorithm
    :param plain_password: str -> The plain text password
    :param hashed_password: str -> The hashed password
    :return: bool -> Tells if plain matches the hashed password
    """
    return verify_password_with_context(plain_password, hashed_password, default_pwd_context)


def get_password_hash(password):
    """
    Hash a password by using the default hashing algorithm
    :param password: str -> The plain text password
    :return: str -> The hashed password
    """
    return get_password_hash_with_context(password, default_pwd_context)


def create_access_token(user: UserModel, expires_delta: timedelta = None) -> str:
    """
    Create an access token for a user
    :param user: CTSUser -> The user
    :param expires_delta: timedelta -> The expiration of the token. If not given a default will be used
    :return: str -> A token
    """
    load_all_config()
    to_encode = user.dict()
    if not expires_delta:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return __generate_jwt_token(to_encode, expires_delta)


def __generate_jwt_token(to_encode: dict, expires_delta: timedelta) -> str:
    """
    Generates a JWT type
    :param to_encode: dict -> payload to encode
    :param expires_delta: timedelta -> expiration of the token
    :return: str -> token
    """
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(token_info: RefreshTokenInfo, expires_delta: timedelta = None) -> str:
    """
    creates a refresh token
    :param token_info: RefreshTokenInfo -> with origin as username and access token
    :param expires_delta: timedelta -> expiration of the refresh token
    :return: str -> the refresh token
    """
    load_all_config()
    if not expires_delta:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES * 2)
    if token_info.access_token:
        token_info.access_token_hash = hash_token(token_info.access_token)
    else:
        raise ValueError("missing access token")
    to_encode = token_info.dict(exclude={"access_token"})
    return __generate_jwt_token(to_encode, expires_delta)


def verify_refresh_token_info(refresh_token: str, access_token: str, origin: str) -> Optional[RefreshTokenInfo]:
    """
    Get info about refresh token (origin and hash of access token)
    :param refresh_token: str -> The refresh token
    :param access_token: str -> The corresponding access token
    :param origin: str -> The origin (username)
    :return: RefreshTokenInfo -> Object holder info of the refresh token
    """
    load_all_config()
    decode_options = {}
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM], options=decode_options)
        _origin: str = payload.get("origin")
        _access_token_hash: str = payload.get("access_token_hash")
        if not _origin or not _access_token_hash:
            return None
        if _origin != origin:
            return None
        access_token_hash = hash_token(access_token)
        if _access_token_hash != access_token_hash:
            return None
        return RefreshTokenInfo(origin=origin, access_token_hash=access_token_hash)
    except PyJWTError:
        return None


async def get_current_user_optional(token: str = Depends(optional_oauth2_scheme)) -> Optional[UserModel]:
    """
    Optionally get user based on the value of the authorization header
    :param token: str -> token read from authorization header
    :return: CTSUser -> The user if found, null otherwise
    """
    if token:
        return await get_current_user(token)
    return None


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserModel:
    """
    Get connected user based on the authorization header
    :param token: str -> The token read from authorization header
    :return: CTSUser -> The user read
    :raises HTTPException when token is not valid
    """
    load_all_config()
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        decode_options = {}
        # TODO check expiration date of token or add options = {"verify_exp": True} option jwt.decode
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM], options=decode_options)
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
        user = UserModel(**payload)
    except PyJWTError:
        raise credentials_exception
    if user is None:
        raise credentials_exception
    return user
