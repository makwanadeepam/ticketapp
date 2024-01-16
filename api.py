from fastapi import FastAPI, Depends, HTTPException, Header
from jose import jwt
from pydantic import BaseModel, EmailStr, Field
import json
import os
from datetime import datetime, timedelta

app = FastAPI()

DATABASE_FILE = "local_database.json"

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr = Field(..., max_length=50)
    password: str = Field(..., min_length=8, max_length=50)

class Query(BaseModel):
    complaint_category: str = Field(..., max_length=50)
    postdate: str = Field(..., max_length=50)
    description: str = Field(..., max_length=200)
    photos: list = Field(..., min_items=1)
    status: str = Field(..., max_length=50)
    location: str = Field(..., max_length=50)

def create_jwt_token(data: dict, expires_delta: timedelta):
    expire = datetime.utcnow() + expires_delta
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Header(...)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

if not os.path.exists(DATABASE_FILE):
    with open(DATABASE_FILE, 'w') as f:
        json.dump({"users": {}, "queries": {}}, f)

def read_data():
    with open(DATABASE_FILE, 'r') as f:
        return json.load(f)

def write_data(data):
    with open(DATABASE_FILE, 'w') as f:
        json.dump(data, f)

@app.post("/signup")
def signup(user: User):
    data = read_data()

    if user.username in data["users"] or user.email in [u["email"] for u in data["users"].values()]:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    user_id = len(data["users"]) + 1
    data["users"][user_id] = user.dict()
    write_data(data)

    return {"message": "User created successfully"}

@app.post("/login")
def login(username: str = Header(...), password: str = Header(...)):
    data = read_data()

    for user_data in data["users"].values():
        if user_data["username"] == username and user_data["password"] == password:
            expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            session_token = create_jwt_token({"sub": user_data["username"]}, expires_delta)
            return {"access_token": session_token, "token_type": "bearer"}

    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/createquery")
def create_query(
    complaint_category: str = Header(...),
    postdate: str = Header(...),
    description: str = Header(...),
    photos: list = Header(...),
    status: str = Header(...),
    location: str = Header(...),
    token: dict = Depends(verify_token),
):
    data = read_data()
    user_id = token['sub']

    query_id = len(data["queries"]) + 1
    query_data = {
        "user_id": user_id,
        "complaint_category": complaint_category,
        "postdate": postdate,
        "description": description,
        "photos": photos,
        "status": status,
        "location": location,
    }
    data["queries"][query_id] = query_data
    write_data(data)

    return {"message": "Query created successfully"}

@app.get("/allqueries")
def get_all_queries(token: dict = Depends(verify_token)):
    data = read_data()
    user_id = token['sub']

    user_queries = [query for query in data["queries"].values() if query.get("user_id") == user_id]

    return {"queries": user_queries}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
      
