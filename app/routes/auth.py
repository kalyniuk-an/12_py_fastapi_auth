from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.repository_users import create_user, get_user_by_email, update_token
from app.schemas import TokenModel, UserCreate, UserResponse
from app.services.auth import auth_service


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def signup(body: UserCreate, db: Session=Depends(get_db)):
    existing_user = get_user_by_email(body.email, db)

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account with this email already exists",
        )

    user = create_user(body, db)
    return user


@router.post("/login", response_model=TokenModel)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = get_user_by_email(form_data.username, db)

    if user is None or not auth_service.verify_password(
        form_data.password,
        user.password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = await auth_service.create_access_token(user.email)
    refresh_token = await auth_service.create_refresh_token(user.email)

    update_token(user, refresh_token, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
