from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Union
from passlib.context import CryptContext

test_DB = {
    
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashedP": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


app = FastAPI()


oauth2S = OAuth2PasswordBearer("/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    full_name: Union [str, None] = None
    email: Union [str, None] = None
    disabled: Union [bool, None] = None
    
class UserInDB(User):
    hashedP: str

def get_user(db, username):
    if username in db:
        userData = db[username]
        return UserInDB(**userData)
    return []

def verificaPassword(password, hashedP):
    return pwd_context.verify(password, hashedP)

        
def autenticate(db, username, password):
    user = get_user(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="No se encontro el usuario", headers = {"WWW-Authenticate": "Bearer"})
    if not verificaPassword(password, user.hashedP):
        raise HTTPException(status_code=401, detail="No se pudo validar el usuario", headers = {"WWW-Authenticate": "Bearer"})
    return user
    

@app.get("/")
def raiz():
    return "Bienvenido a mi API"

@app.get("/users/me")
def usuario(token: str = Depends(oauth2S)):
    print(token)
    return "Soy un usuario"

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = autenticate(test_DB, form_data.username, form_data.password)
    print(user)
    return {
        "access_token": "Nekocat",
        "token_type": "bearer"
    }
    