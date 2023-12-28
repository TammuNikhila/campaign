from fastapi.responses import JSONResponse
from fastapi import FastAPI, HTTPException, Depends, status
from datetime import date, datetime, timedelta
import mysql.connector
from jose import JWTError, jwt
from typing import Optional, List
from fastapi import Form
from typing import Dict
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from functools import wraps
import os
import jwt
from dateutil import parser
import re
from auth import JWTBearer, create_jwt_token, decode_jwt_token
from dotenv import load_dotenv
load_dotenv(".env")

# Function to connect to the MySQL database
def connect_to_mysql():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('host'),
            user=os.getenv('user'),
            password=os.getenv('password'),
            database=os.getenv('database')
        )
        return connection
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Function to verify the user credentials against the user_table
def verify_user(username: str, password: str, connection):
    try:
        cursor = connection.cursor()

        # Check if the user exists in the user_table
        query = f"SELECT * FROM user_table WHERE username = '{username}' AND password = '{password}';"
        cursor.execute(query)
        user_data = cursor.fetchone()

        cursor.close()

        # If user_data is not None, convert it to a dictionary
        if user_data:
            user_dict = {
                "username": user_data[1],
                "role": user_data[3],
            }
            print("user_dict:", user_dict)
            return user_dict
        else:
            return None

    except Exception as e:
        print(f"Error verifying user: {e}")
        return None

# Function to create a new user in the user_table
def create_user(username: str, password: str, connection):
    try:
        cursor = connection.cursor()

        # Insert a new user record with default role 'general'
        insert_query = f"INSERT INTO user_table (username, password, role) VALUES ('{username}', '{password}', 'general');"
        cursor.execute(insert_query)

        connection.commit()
        cursor.close()

        return {"username": username, "role": "general"}

    except Exception as e:
        print(f"Error creating user: {e}")
        return None
    
# Function to convert date objects to strings
def convert_dates_to_strings(result):
    converted_result = []
    for row in result:
        converted_row = [str(value) if isinstance(value, date) else value for value in row]
        converted_result.append(converted_row)
    return converted_result

# Function to check if the user is an admin
def check_admin(current_user: dict = Depends(JWTBearer())):
    print(current_user)
    user_data = decode_jwt_token(current_user)
    if user_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can perform this action.")
    
def get_user_role(current_user: dict = Depends(JWTBearer())):
    user_data = decode_jwt_token(current_user)
    print("User_data:", user_data)

    username = user_data.get("sub")
    role = user_data.get("role")
    
    print("username:", username)
    print("role:", role)
    
    if role != "admin":
        print("General")
        return "general"
    else:
        print("Admin")
        return "admin"

DATE_FORMAT_REGEX = re.compile(r"\d{4}-\d{2}-\d{2}")

# Function to validate date format using regex
def validate_date_format(date_str):
    if DATE_FORMAT_REGEX.match(date_str):
        return date.fromisoformat(date_str)
    else:
        raise HTTPException(status_code=422, detail="Invalid date format. Please provide the date in a valid format (YYYY-MM-DD).")