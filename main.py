from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Union
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt


test_DB = {
    
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashedP": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

# Esto debe ir en la DB y moverse de aqui para seguridad
SECRET_KEY="GATITO_BONITO"
ALGORITHM = "HS256"

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
    
def createToken(data: dict, timeExpire: Union[datetime, None]= None):
    dataCopy = data.copy()
    if timeExpire is None:
        expires = datetime.utcnow() + timedelta(minutes=15)
    else: 
        expires = datetime.utcnow() + timeExpire
    dataCopy.update({"exp": expires})
    jwtToken = jwt.encode(dataCopy, key=SECRET_KEY, algorithm=ALGORITHM)
    return jwtToken

def getCurrentUser(token: str = Depends(oauth2S)):
    try: 
        tokenDecode = jwt.decode(token, key=SECRET_KEY, algorithms=[ALGORITHM])
        username = tokenDecode.get("sub")
        if username == None:
            raise HTTPException(status_code=401, detail="No se puede validar las credenciales de usuario", headers={"WWW-Authenticate": "Bearer"})
    except JWTError:
        raise HTTPException(status_code=401, detail="No se puede validar las credenciales de usuario", headers={"WWW-Authenticate": "Bearer"})
    user = get_user(test_DB, username)
    if not user:
        raise HTTPException(status_code=401, detail="No se puede validar las credenciales de usuario", headers={"WWW-Authenticate": "Bearer"})
    return user

def getUserDisable(user: User = Depends(getCurrentUser)):
    if user.disabled:
        raise HTTPException(status_code=400, detail= "Inactive User")
    return User
    


@app.get("/")
def raiz():
    return "Bienvenido a mi API"

@app.get("/users/me")
def usuario(user: User = Depends(getUserDisable)):
    return user

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = autenticate(test_DB, form_data.username, form_data.password)
    accesTokenExpires = timedelta(minutes=30)
    jwtToken = createToken({"sub": user.username}, accesTokenExpires)
    return {
        "access_token": jwtToken ,
        "token_type": "bearer"
    }
    