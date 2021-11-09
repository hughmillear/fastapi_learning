# main.py

## sql relation databases & orm
# sqlite used here, there is template for
# postgres here: https://github.com/tiangolo/full-stack-fastapi-postgresql

from typing import List

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# use the direct Session class from sqlalchemy as the type hint
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/users/{user_id}/items/", response_model=schemas.Item)
def create_item_for_user(
    user_id: int, item: schemas.ItemCreate, db: Session = Depends(get_db)
):
    return crud.create_user_item(db=db, item=item, user_id=user_id)


@app.get("/items/", response_model=List[schemas.Item])
def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    items = crud.get_items(db, skip=skip, limit=limit)
    return items


# ## CORS
# from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware

# app = FastAPI()

# origins = [
#     "http://localhost.tiangolo.com",
#     "https://localhost.tiangolo.com",
#     "http://localhost",
#     "http://localhost:8000",
#     "http://localhost:8080",
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# @app.get("/")
# async def main():
#     return {"message": "Hello World"}



# ## middleware
# import time
# from fastapi import FastAPI, Request

# app = FastAPI()

# @app.middleware("http")
# async def add_process_time_header(request: Request, call_next):
#     start_time = time.time()
#     response = await call_next(request)
#     process_time = time.time() - start_time
#     response.headers["X-Process-Time"] = str(process_time)
#     return response



# ## security - oauth2 with password hassing and jwt bearer tokens
# from datetime import datetime, timedelta
# from typing import Optional

# from fastapi import Depends, FastAPI, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from jose import JWTError, jwt
# from passlib.context import CryptContext
# from pydantic import BaseModel

# # to get a string like this run:
# # openssl rand -hex 32
# SECRET_KEY = "d72233f7d15616d1efaef9a153c31919230a2c94674ad6e1541d464ad3ce46b6"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30


# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
#         "disabled": False,
#     }
# }


# class Token(BaseModel):
#     access_token: str
#     token_type: str


# class TokenData(BaseModel):
#     username: Optional[str] = None


# class User(BaseModel):
#     username: str
#     email: Optional[str] = None
#     full_name: Optional[str] = None
#     disabled: Optional[bool] = None


# class UserInDB(User):
#     hashed_password: str


# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# app = FastAPI()


# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)


# def get_password_hash(password):
#     return pwd_context.hash(password)


# def get_user(db, username: str):
#     if username in db:
#         user_dict = db[username]
#         return UserInDB(**user_dict)


# def authenticate_user(fake_db, username: str, password: str):
#     user = get_user(fake_db, username)
#     if not user:
#         return False
#     if not verify_password(password, user.hashed_password):
#         return False
#     return user


# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt


# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception
#     user = get_user(fake_users_db, username=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user


# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user


# @app.post("/token", response_model=Token)
# async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(fake_users_db, form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user.username}, expires_delta=access_token_expires
#     )
#     return {"access_token": access_token, "token_type": "bearer"}


# @app.get("/users/me/", response_model=User)
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     return current_user


# @app.get("/users/me/items/")
# async def read_own_items(current_user: User = Depends(get_current_active_user)):
#     return [{"item_id": "Foo", "owner": current_user.username}]



# ## security - simple OAuth2 with password and bearer
# from typing import Optional

# from fastapi import Depends, FastAPI, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel

# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "fakehashedsecret",
#         "disabled": False,
#     },
#     "alice": {
#         "username": "alice",
#         "full_name": "Alice Wonderson",
#         "email": "alice@example.com",
#         "hashed_password": "fakehashedsecret2",
#         "disabled": True,
#     },
# }

# app = FastAPI()


# def fake_hash_password(password: str):
#     return "fakehashed" + password


# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# class User(BaseModel):
#     username: str
#     email: Optional[str] = None
#     full_name: Optional[str] = None
#     disabled: Optional[bool] = None


# class UserInDB(User):
#     hashed_password: str


# def get_user(db, username: str):
#     if username in db:
#         user_dict = db[username]
#         return UserInDB(**user_dict)


# def fake_decode_token(token):
#     # This doesn't provide any security at all
#     # Check the next version
#     user = get_user(fake_users_db, token)
#     return user


# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     user = fake_decode_token(token)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     return user


# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user


# @app.post("/token")
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     user = UserInDB(**user_dict)
#     hashed_password = fake_hash_password(form_data.password)
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")

#     return {"access_token": user.username, "token_type": "bearer"}


# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     return current_user



# ## security - no handling of actual auth
# from typing import Optional

# from fastapi import Depends, FastAPI
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel

# app = FastAPI()

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# class User(BaseModel):
#     username: str
#     email: Optional[str] = None
#     full_name: Optional[str] = None
#     disabled: Optional[bool] = None

# def fake_decode_token(token):
#     return User(
#         username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
#     )


# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     user = fake_decode_token(token)
#     return user


# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_user)):
#     return current_user




# ## dependencies with yield
# async def get_db():
#     db = DBSession()
#     try:
#         yield db
#     finally:
#         db.close()

# # sub-dependencies with yield
# from fastapi import Depends


# async def dependency_a():
#     dep_a = generate_dep_a()
#     try:
#         yield dep_a
#     finally:
#         dep_a.close()


# async def dependency_b(dep_a=Depends(dependency_a)):
#     dep_b = generate_dep_b()
#     try:
#         yield dep_b
#     finally:
#         dep_b.close(dep_a)


# async def dependency_c(dep_b=Depends(dependency_b)):
#     dep_c = generate_dep_c()
#     try:
#         yield dep_c
#     finally:
#         dep_c.close(dep_b)

# # advanced
# class MySuperContextManager:
#     def __init__(self):
#         self.db = DBSession()

#     def __enter__(self):
#         return self.db

#     def __exit__(self, exc_type, exc_value, traceback):
#         self.db.close()


# async def get_db():
#     with MySuperContextManager() as db:
#         yield db



# ## dependencies in path operation decorators
# # initial authorisation implementation example
# from fastapi import Depends, FastAPI, Header, HTTPException

# # app = FastAPI() ## path specific dependencies

# async def verify_token(x_token: str = Header(...)):
#     if x_token != "fake-super-secret-token":
#         raise HTTPException(status_code=400, detail="X-Token header invalid")


# async def verify_key(x_key: str = Header(...)):
#     if x_key != "fake-super-secret-key":
#         raise HTTPException(status_code=400, detail="X-Key header invalid")
#     return x_key

# ## path specific dependencies
# # @app.get("/items/", dependencies=[Depends(verify_token), Depends(verify_key)])
# # async def read_items():
# #     return [{"item": "Foo"}, {"item": "Bar"}]

# ## global dependencies
# app = FastAPI(dependencies=[Depends(verify_token), Depends(verify_key)])

# @app.get("/items/")
# async def read_items():
#     return [{"item": "Portal Gun"}, {"item": "Plumbus"}]

# @app.get("/users/")
# async def read_users():
#     return [{"username": "Rick"}, {"username": "Morty"}]




# ## sub-dependencies
# from typing import Optional

# from fastapi import Cookie, Depends, FastAPI

# app = FastAPI()


# def query_extractor(q: Optional[str] = None):
#     return q


# def query_or_cookie_extractor(
#     q: str = Depends(query_extractor), last_query: Optional[str] = Cookie(None)
# ):
#     if not q:
#         return last_query
#     return q


# @app.get("/items/")
# async def read_query(query_or_default: str = Depends(query_or_cookie_extractor)):
#     return {"q_or_cookie": query_or_default}




# ## classes as dependencies
# from typing import Optional

# from fastapi import Depends, FastAPI

# app = FastAPI()


# fake_items_db = [{"item_name": "Foo"}, {"item_name": "Bar"}, {"item_name": "Baz"}]


# class CommonQueryParams:
#     def __init__(self, q: Optional[str] = None, skip: int = 0, limit: int = 100):
#         self.q = q
#         self.skip = skip
#         self.limit = limit


# @app.get("/items/")
# # async def read_items(commons: CommonQueryParams = Depends(CommonQueryParams)):
# ## FastAPI provides a shortcut for these cases, 
# # in where the dependency is specifically a class that 
# # FastAPI will "call" to create an instance of the class itself.
# # FastAPI can then use the CommonQueryParams class even without defining it
# async def read_items(commons: CommonQueryParams = Depends()): 
#     response = {}
#     if commons.q:
#         response.update({"q": commons.q})
#     items = fake_items_db[commons.skip : commons.skip + commons.limit]
#     response.update({"items": items})
#     return response


# ## body updates
# from typing import Any, List, Optional, Dict

# from fastapi import FastAPI
# from fastapi.encoders import jsonable_encoder
# from pydantic import BaseModel

# app = FastAPI()


# class Item(BaseModel):
#     name: Optional[str] = None
#     description: Optional[str] = None
#     price: Optional[float] = None
#     tax: float = 10.5
#     tags: List[str] = []


# items: Dict[str, Dict[str, Any]] = {
#     "foo": {"name": "Foo", "price": 50.2},
#     "bar": {"name": "Bar", "description": "The bartenders", "price": 62, "tax": 20.2},
#     "baz": {"name": "Baz", "description": None, "price": 50.2, "tax": 10.5, "tags": []},
# }


# @app.get("/items/{item_id}", response_model=Item)
# async def read_item(item_id: str):
#     return items[item_id]


# @app.put("/items/{item_id}", response_model=Item)
# async def put_update_item(item_id: str, item: Item):
#     update_item_encoded = jsonable_encoder(item)
#     items[item_id] = update_item_encoded
#     return update_item_encoded

# @app.patch("/items/{item_id}", response_model=Item)
# async def patch_update_item(item_id: str, item: Item):
#     stored_item_data = items[item_id]
#     stored_item_model = Item(**stored_item_data)
#     update_data = item.dict(exclude_unset=True)
#     updated_item = stored_item_model.copy(update=update_data)
#     items[item_id] = jsonable_encoder(updated_item)
#     return updated_item



# ## json encoder
# from datetime import datetime
# from typing import Optional

# from fastapi import FastAPI
# from fastapi.encoders import jsonable_encoder
# from pydantic import BaseModel

# fake_db = {}


# class Item(BaseModel):
#     title: str
#     timestamp: datetime
#     description: Optional[str] = None


# app = FastAPI()


# @app.put("/items/{id}")
# def update_item(id: str, item: Item):
#     json_compatible_item_data = jsonable_encoder(item)
#     fake_db[id] = json_compatible_item_data




# ## path operation configuration
# from typing import Optional, Set

# from fastapi import FastAPI
# from pydantic import BaseModel

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None
#     tags: Set[str] = set()


# @app.post("/items/", response_model=Item, summary="Create an item", tags=["items"])
# async def create_item(item: Item):
#     """
#     Create an item with all the information:

#     - **name**: each item must have a name
#     - **description**: a long description
#     - **price**: required
#     - **tax**: if the item doesn't have tax, you can omit this
#     - **tags**: a set of unique tag strings for this item
#     """
#     return item


# @app.get("/items/", tags=["items"])
# async def read_items():
#     return [{"name": "Foo", "price": 42}]


# @app.get("/users/", tags=["users"])
# async def read_users():
#     return [{"username": "johndoe"}]


# @app.get("/elements/", tags=["items"], deprecated=True)
# async def read_elements():
#     return [{"item_id": "Foo"}]




# ## handling errors
# from fastapi import FastAPI, HTTPException, Request, status
# from fastapi.responses import JSONResponse, PlainTextResponse
# from fastapi.exceptions import RequestValidationError
# from starlette.exceptions import HTTPException as StarletteHTTPException
# from fastapi.encoders import jsonable_encoder
# from pydantic import BaseModel
# from fastapi.exception_handlers import (
#     http_exception_handler,
#     request_validation_exception_handler,
# )
# from starlette.exceptions import HTTPException as StarletteHTTPException


# # class UnicornException(Exception):
# #     def __init__(self, name: str):
# #         self.name = name

# app = FastAPI()

# # items = {"foo": "The Foo Wrestlers"}

# # @app.exception_handler(StarletteHTTPException)
# # async def http_exception_handler(request, exc):
# #     return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


# # @app.exception_handler(RequestValidationError)
# # async def validation_exception_handler(request, exc):
# #     return PlainTextResponse(str(exc), status_code=400)

# # @app.get("/items-header/{item_id}")
# # async def read_item_header(item_id: str):
# #     if item_id not in items:
# #         raise HTTPException(
# #             status_code=404,
# #             detail="Item not found",
# #             headers={"X-Error": "There goes my error"},
# #         )
# #     return {"item": items[item_id]}


# # @app.get("/items/{item_id}")
# # async def read_item(item_id: int):
# #     if item_id == 3:
# #         raise HTTPException(status_code=418, detail="Nope! I don't like 3.")
# #     return {"item_id": item_id}

# # @app.exception_handler(UnicornException)
# # async def unicorn_exception_handler(request: Request, exc: UnicornException):
# #     return JSONResponse(
# #         status_code=418,
# #         content={"message": f"Oops! {exc.name} did something. There goes a rainbow..."},
# #     )


# # @app.get("/unicorns/{name}")
# # async def read_unicorn(name: str):
# #     if name == "yolo":
# #         raise UnicornException(name=name)
# #     return {"unicorn_name": name}


# # @app.exception_handler(RequestValidationError)
# # async def validation_exception_handler(request: Request, exc: RequestValidationError):
# #     return JSONResponse(
# #         status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
# #         content=jsonable_encoder({"detail": exc.errors(), "body": exc.body}),
# #     )


# # class Item(BaseModel):
# #     title: str
# #     size: int


# # @app.post("/items/")
# # async def create_item(item: Item):
# #     return item

# @app.exception_handler(StarletteHTTPException)
# async def custom_http_exception_handler(request, exc):
#     print(f"OMG! An HTTP error!: {repr(exc)}")
#     return await http_exception_handler(request, exc)


# @app.exception_handler(RequestValidationError)
# async def validation_exception_handler(request, exc):
#     print(f"OMG! The client sent invalid data!: {exc}")
#     return await request_validation_exception_handler(request, exc)


# @app.get("/items/{item_id}")
# async def read_item(item_id: int):
#     if item_id == 3:
#         raise HTTPException(status_code=418, detail="Nope! I don't like 3.")
#     return {"item_id": item_id}



# ## request forms and files in the same request
# from fastapi import FastAPI, File, Form, UploadFile

# app = FastAPI()


# @app.post("/files/")
# async def create_file(
#     file: bytes = File(...), fileb: UploadFile = File(...), token: str = Form(...)
# ):
#     return {
#         "file_size": len(file),
#         "token": token,
#         "fileb_content_type": fileb.content_type,
#     }


# ## request files initial
# from typing import List
# from fastapi import FastAPI, File, UploadFile
# from fastapi.responses import HTMLResponse

# app = FastAPI()


# @app.post("/file/")
# async def create_file(file: bytes = File(...)):
#     # contents = file.decode("utf-8")
#     # print(contents)
#     return {"file_size": len(file)}


# @app.post("/uploadfile/")
# async def create_upload_file(file: UploadFile = File(...)):
#     contents = await file.read()
#     # if isinstance(contents, bytes):
#     #     print("the file type was bytes")
#     #     contents = contents.decode("utf-8")
#     # print(contents)
#     return {"filename": file.filename}

# @app.post("/files/")
# async def create_files(files: List[bytes] = File(...)):
#     return {"file_sizes": [len(file) for file in files]}

# @app.post("/uploadfiles/")
# async def create_upload_files(files: List[UploadFile] = File(...)):
#     return {"filenames": [file.filename for file in files]}

# @app.get("/")
# async def main():
#     content = """
# <body>
# <h1>/files</h1>
# <form action="/files/" enctype="multipart/form-data" method="post">
# <input name="files" type="file" multiple>
# <input type="submit">
# </form>
# <h1>/uploadfiles</h1>
# <form action="/uploadfiles/" enctype="multipart/form-data" method="post">
# <input name="files" type="file" multiple>
# <input type="submit">
# </form>
# </body>
#     """
#     return HTMLResponse(content=content)




# ## request forms
# from fastapi import FastAPI, Form

# app = FastAPI()


# @app.post("/login/")
# async def login(username: str = Form(...), password: str = Form(...)):
#     return {"username": username}


## reponse codes
# from fastapi import FastAPI, status
# @app.post("/items/", status_code=status.HTTP_201_CREATED)
# async def create_item(name: str):
#     return {"name": name}


# ## Extra model - multiple model type returns
# from typing import Union, List, Dict, TypeVar

# from fastapi import FastAPI
# from pydantic import BaseModel

# app = FastAPI()


# # class BaseItem(BaseModel):
# #     description: str
# #     type: str


# # class CarItem(BaseItem):
# #     type = "car"


# # class PlaneItem(BaseItem):
# #     type = "plane"
# #     size: int


# # items = {
# #     "item1": {"description": "All my friends drive a low rider", "type": "car"},
# #     "item2": {
# #         "description": "Music is my aeroplane, it's my aeroplane",
# #         "type": "plane",
# #         "size": 5,
# #     },
# # }

# # class AllItems(BaseItem):
# #     __root__: Union[PlaneItem, CarItem]

# # AllItems = TypeVar('AllItems',PlaneItem,CarItem)

# # @app.get("/items/{item_id}", response_model=AllItems)
# # async def read_item(item_id: str):
# #     return items[item_id]


# # # mypy complains, this is because the dicts are inconsistent which is not great
# # @app.get("/items/{item_id}", response_model=Union[PlaneItem, CarItem])
# # async def read_item(item_id: str):
# #     return items[item_id]


# class ItemSimple(BaseModel):
#     name: str
#     description: str

# simple_items = [
#     {"name": "Foo", "description": "There comes my hero"},
#     {"name": "Red", "description": "It's my aeroplane"},
# ]


# @app.get("/simple_items/", response_model=List[ItemSimple])
# async def read_simple_items():
#     return simple_items

# @app.get("/keyword-weights/", response_model=Dict[str, float])
# async def read_keyword_weights():
#     return {"foo": 2.3, "bar": 3.4}


# ## Extra Models - User example and deduplication
# from typing import Optional

# from fastapi import FastAPI
# from pydantic import BaseModel, EmailStr

# app = FastAPI()


# class UserBase(BaseModel):
#     username: str
#     email: EmailStr
#     full_name: Optional[str] = None


# class UserIn(UserBase):
#     password: str


# class UserOut(UserBase):
#     pass


# class UserInDB(UserBase):
#     hashed_password: str



# def fake_password_hasher(raw_password: str):
#     return "supersecret" + raw_password


# def fake_save_user(user_in: UserIn):
#     hashed_password = fake_password_hasher(user_in.password)
#     user_in_db = UserInDB(**user_in.dict(), hashed_password=hashed_password)
#     print("User saved! ..not really")
#     return user_in_db


# @app.post("/user/", response_model=UserOut)
# async def create_user(user_in: UserIn):
#     user_saved = fake_save_user(user_in)
#     return user_saved




# ## response model
# from typing import List, Optional

# from fastapi import FastAPI
# from pydantic import BaseModel, EmailStr

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None
#     tags: List[str] = []


# # response_model is what goes out in response,
# # not necessarily what comes in via the request
# @app.post("/items/", response_model=Item)
# async def create_item(item: Item):
#     return item


# class UserIn(BaseModel):
#     username: str
#     password: str
#     email: EmailStr
#     full_name: Optional[str] = None


# # # Don't do this in production!
# # @app.post("/user/", response_model=UserIn)
# # async def create_user(user: UserIn):
# #     return user

# class UserOut(BaseModel):
#     username: str
#     email: EmailStr
#     full_name: Optional[str] = None


# @app.post("/user/", response_model=UserOut)
# async def create_user(user: UserIn):
#     return user



# ## headers
# from typing import Optional, List
# from fastapi import FastAPI, Header

# app = FastAPI()


# # @app.get("/items/")
# # async def read_items(user_agent: Optional[str] = Header(None)):
# #     return {"User-Agent": user_agent}

# # @app.get("/items/")
# # async def read_items(
# #     strange_header: Optional[str] = Header(None, convert_underscores=False)
# # ):
# #     return {"strange_header": strange_header}

# @app.get("/items/")
# async def read_items(x_token: Optional[List[str]] = Header(None)):
#     return {"X-Token values": x_token}

# ## extra data types
# from datetime import datetime, time, timedelta
# from typing import Optional
# from uuid import UUID

# from fastapi import Body, FastAPI

# app = FastAPI()


# @app.put("/items/{item_id}")
# async def read_items(
#     item_id: UUID,
#     start_datetime: Optional[datetime] = Body(None),
#     end_datetime: Optional[datetime] = Body(None),
#     repeat_at: Optional[time] = Body(None),
#     process_after: Optional[timedelta] = Body(None),
# ):
#     start_process = start_datetime + process_after
#     duration = end_datetime - start_process
#     return {
#         "item_id": item_id,
#         "start_datetime": start_datetime,
#         "end_datetime": end_datetime,
#         "repeat_at": repeat_at,
#         "process_after": process_after,
#         "start_process": start_process,
#         "duration": duration,
#     }


# ## schema extra sample
# from typing import Optional

# from fastapi import FastAPI, Body
# from pydantic import BaseModel

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None

#     class Config:

#         schema_extra = {
#             "example": {
#                 "name": "Foo",
#                 "description": "A very nice Item",
#                 "price": 35.4,
#                 "tax": 3.2,
#             }
#         }


# @app.put("/items/{item_id}")
# async def update_item(item_id: int, item: Item):
#     results = {"item_id": item_id, "item": item}
#     return results


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None

# ## doesn't work currently
# @app.put("/items/{item_id}")
# async def update_item(
#     *,
#     item_id: int,
#     item: Item = Body(
#         ...,
#         examples={
#             "normal": {
#                 "summary": "A normal example",
#                 "description": "A **normal** item works correctly.",
#                 "value": {
#                     "name": "Foo",
#                     "description": "A very nice Item",
#                     "price": 35.4,
#                     "tax": 3.2,
#                 },
#             },
#             "converted": {
#                 "summary": "An example with converted data",
#                 "description": "FastAPI can convert price `strings` to actual `numbers` automatically",
#                 "value": {
#                     "name": "Bar",
#                     "price": "35.4",
#                 },
#             },
#             "invalid": {
#                 "summary": "Invalid data is rejected with an error",
#                 "value": {
#                     "name": "Baz",
#                     "price": "thirty five point four",
#                 },
#             },
#         },
#     ),
# ):
#     results = {"item_id": item_id, "item": item}
#     return results


# ## body - nested models
# from typing import Dict, List, Optional, Set

# from fastapi import FastAPI
# from pydantic import BaseModel, HttpUrl

# app = FastAPI()


# class Image(BaseModel):
#     url: HttpUrl
#     name: str


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None
#     tags: Set[str] = set()
#     images: Optional[List[Image]] = None


# class Offer(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     items: List[Item]


# @app.put("/items/{item_id}")
# async def update_item(item_id: int, item: Item):
#     results = {"item_id": item_id, "item": item}
#     return results


# @app.post("/offers/")
# async def create_offer(offer: Offer):
#     return offer

# @app.post("/images/multiple/")
# async def create_multiple_images(images: List[Image]):
#     # for image in images:
#     #     image.url.lower() # comes from autocomplete
#     return images

# @app.post("/index-weights/")
# async def create_index_weights(weights: Dict[int, float]):
#     return weights


# ##  body - fields
# # how to embed more validation and metadata directly in the
# # pydantic models using Field
# from typing import Optional

# from fastapi import Body, FastAPI
# from pydantic import BaseModel, Field

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = Field(
#         None, title="The description of the item", max_length=300
#     )
#     price: float = Field(..., ge=0, description="The price must be greater than zero")
#     tax: Optional[float] = None


# @app.put("/items/{item_id}")
# async def update_item(item_id: int, item: Item = Body(..., embed=True)):
#     results = {"item_id": item_id, "item": item}
#     return results


# ## body multiple params
# from typing import Optional

# from fastapi import FastAPI, Body
# from pydantic import BaseModel

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None


# class User(BaseModel):
#     username: str
#     full_name: Optional[str] = None


# @app.put("/items/{item_id}")
# async def update_item(
#     item_id: int, item: Item, user: User, importance: int = Body(...)
# ):
#     results = {"item_id": item_id, "item": item, "user": user, "importance": importance}
#     return results


# {
#     "item": {
#         "name": "Foo",
#         "description": "The pretender",
#         "price": 42.0,
#         "tax": 3.2
#     },
#     "user": {
#         "username": "dave",
#         "full_name": "Dave Grohl"
#     },
#     "importance": 5
# }


# @app.put("/items/{item_id}")
# async def update_item(
#     *,
#     item_id: int = Path(..., title="The ID of the item to get", ge=0, le=1000),
#     q: Optional[str] = None,
#     item: Optional[Item] = None,
# ):
#     results = {"item_id": item_id}
#     if q:
#         results.update({"q": q})
#     if item:
#         results.update({"item": item})
#     return results


# # path parameters and validation
# from typing import Optional

# from fastapi import FastAPI, Path, Query

# app = FastAPI()


# @app.get("/items/{item_id}")
# async def read_items(
#     item_id: int = Path(..., title="The ID of the item to get", ge=1, le=12),
#     q: Optional[str] = Query(None, alias="item-query"),
#     size: float = Query(..., ge=0, le=10.5),
# ):
#     results = {"item_id": item_id}
#     if q:
#         results.update({"q": q})
#     return results


# from typing import List, Optional


# ## more metadata, and alias parameters plus deprecation
# from fastapi import FastAPI, Query

# app = FastAPI()


# @app.get("/items/")
# async def read_items(
#     q: Optional[str] = Query(
#         None,
#         alias="item-query",
#         title="Query string",
#         description="Query string for the items to search in the database that have a good match",
#         min_length=3,
#         max_length=50,
#         regex="^fixedquery$",
#         deprecated=True,
#     )
# ):
#     results = {"items": [{"item_id": "Foo"}, {"item_id": "Bar"}]}
#     if q:
#         results.update({"q": q})
#     return results

# # additional validation with Query and required input
# from fastapi import FastAPI, Query

# app = FastAPI()

# # no default values
# @app.get("/items/")
# async def read_items(q: Optional[List[str]] = Query(None)):
#     query_items = {"q": q}
#     return query_items

# # with default values
# @app.get("/items/")
# async def read_items(q: List[str] = Query(["foo", "bar"])):
#     query_items = {"q": q}
#     return query_items

# # additional validation with Query and required input
# from fastapi import FastAPI, Query
# async def read_items(q: str = Query(default=..., min_length=3)):
#     results = {"items": [{"item_id": "Foo"}, {"item_id": "Bar"}]}
#     if q:
#         results.update({"q": [{"q": q}]})
#     return results


# # pydantic models - base
# from pydantic import BaseModel
# class Item(BaseModel):
#     name: str
#     description: Optional[str] = None
#     price: float
#     tax: Optional[float] = None

# app = FastAPI()

# @app.post('/items/')
# async def create_item(item: Item):
#     item_dict = item.dict()
#     if item.tax:
#         price_with_tax = item.price + item.tax
#         item_dict.update({"price_with_tax": price_with_tax})
#     return item_dict

# # ## required query parameters
# @app.get("/items/{item_id}")
# async def read_user_item(item_id: str, needy: str):
#     item = {"item_id": item_id, "needy": needy}
#     return item

# @app.get("/items2/{item_id}")
# async def read_user_item2(
#     item_id: str, needy: str, skip: int = 0, limit: Optional[int] = None
# ):
#     item = {"item_id": item_id, "needy": needy, "skip": skip, "limit": limit}
#     return item

# ## optional query parameters
# @app.get("/users/{user_id}/items/{item_id}")
# async def read_user_item(
#     user_id: int, item_id: str, q: Optional[str] = None, short: bool = False
# ):
#     item = {"item_id": item_id, "owner_id": user_id}
#     if q:
#         item.update({"q": q})
#     if not short:
#         item.update(
#             {"description": "This is an amazing item that has a long description"}
#         )
#     return item

# @app.get("/items/{item_id}")
# async def read_item(item_id: str, q: Optional[str] = None, short: bool = False):
#     item = {"item_id": item_id}
#     if q:
#         item.update({"q": q})
#     if not short:
#         item.update(
#             {"description": "This is an amazing item that has a long description"}
#         )
#     return item


# import time
# import datetime

# from enum import Enum

# from fastapi import FastAPI


# app = FastAPI()

# fake_items_db = [{"item_name": "Foo"}, {"item_name": "Bar"}, {"item_name": "Baz"}]


# @app.get("/items/")
# async def read_item(skip_initial: int = 0, total_limit: int = 10):
#     return fake_items_db[skip_initial : skip_initial + total_limit]


# @app.get('/')
# async def root():
#    return {"message": "Hello World"}

# class ModelName(str, Enum):
#     alexnet = "alexnet"
#     resnet = "resnet"
#     lenet = "lenet"

# @app.get('/models/{model_name}')
# async def get_model(model_name: ModelName):
#     if model_name == ModelName.alexnet:
#         return {"model_name": model_name, "message": "Deep Learning FTW!"}

#     if model_name.value == "lenet":
#         return {"model_name": model_name, "message": "LeCNN all the images"}

#     return {"model_name": model_name, "message": "Have some residuals"}


# @app.get('/files/{file_path:path}')
# async def read_file(file_path: str):
#    return {"file_path": file_path}


# @app.get('/items/{item_id}')
# async def read_item(item_id: int):
#    return {"item_id": item_id}

# @app.get('/users/me')
# async def read_user_me():
#    return {"user_id": "the current user"}

# @app.get('/users/{user_id}')
# async def read_user(user_id: int):
#    return {"user_id": user_id}

# @app.get('/current_time')
# async def current_time():
#     now = datetime.datetime.now()
#     return {"time": f"{now:%Y-%m-%d}"}

# async def sleeping_async(t: float) -> bool:
#     time.sleep(t)
#     return True

# @app.get('/sleep_async')
# async def go_to_sleep_async():
#    finished_sleeping = await sleeping_async(3)
#    return f"I have awoken after 3 seconds!"

# def sleeping_sync(t: float) -> None:
#     time.sleep(t)
#     return None

# @app.get('/sleep_sync')
# async def go_to_sleep_sync():
#    sleeping_sync(3)
#    return f"I have awoken after 3 seconds!"
