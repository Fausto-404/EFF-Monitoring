from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.models.database import get_db
from app.models.entities import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def user_roles(user: User | None) -> set[str]:
    if not user:
        return set()
    raw = getattr(user, "roles", None)
    roles = {str(item) for item in raw if item} if isinstance(raw, list) else set()
    if getattr(user, "role", None):
        roles.add(str(user.role))
    return roles


def has_role(user: User | None, role: str) -> bool:
    return role in user_roles(user)


def has_any_role(user: User | None, roles: set[str]) -> bool:
    return bool(user_roles(user).intersection(roles))


def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if not has_role(user, "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要管理员权限")
    return user


def require_not_viewer(user: User = Depends(current_user)) -> User:
    roles = user_roles(user)
    if not roles or roles <= {"viewer"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="只读人员无权执行写操作")
    return user
