from fastapi.responses import JSONResponse
from fastapi import FastAPI, Query, HTTPException, Depends, status
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
from dotenv import load_dotenv
load_dotenv(".env")
from auth import JWTBearer, create_jwt_token, decode_jwt_token
from camp_helper import connect_to_mysql, verify_user, create_user, convert_dates_to_strings, check_admin, get_user_role

app = FastAPI()

QUERY= """
    SELECT campaign_id, campaign_name, communication_channel, MIN(start_date) AS start_date, MAX(end_date) AS end_date
    FROM campaign_details
    GROUP BY campaign_id, campaign_name, communication_channel;
"""

# Route to handle user login and provide access token
@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    connection: mysql.connector.connection.MySQLConnection = Depends(connect_to_mysql)
):
    user = verify_user(username, password, connection)

    if not user:
        # If user does not exist, create a new user
        user = create_user(username, password, connection)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create a JWT token with user information
    token_data = {"username": user["username"], "scopes": [user["role"]], "role": user["role"]}
    token = create_jwt_token(token_data)

    return {"access_token": token, "token_type": "bearer"}


# Route to execute the any SQL query
@app.get("/execute_any_query/", dependencies=[Depends(JWTBearer())])
async def execute_query():
    try:
        connection = connect_to_mysql()
        if not connection:
            raise HTTPException(status_code=500, detail="Error connecting to the database")
        
        cursor = connection.cursor()

        cursor.execute(QUERY)

        result = cursor.fetchall()

        converted_result = convert_dates_to_strings(result)

        connection.commit()

        cursor.close()
        connection.close()

        return JSONResponse(content={"result": converted_result}, status_code=200)

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error executing SQL query: {e}")
    
@app.get("/create_table/", dependencies=[Depends(check_admin)])
async def create_table(
    table_name: str
):
    try:
        connection = connect_to_mysql()
        if not connection:
            raise HTTPException(status_code=500, detail="Error connecting to the database")

        cursor = connection.cursor()

        table_exists_query = "SHOW TABLES LIKE '{table_name}';"
        cursor.execute(table_exists_query)
        existing_tables = cursor.fetchall()

        if existing_tables:
            cursor.close()
            connection.close()
            return JSONResponse(content={"result": "Table already exists"}, status_code=200)
        
        QUERY = f"""
            CREATE TABLE {table_name} AS
            SELECT campaign_id, campaign_name, communication_channel, MIN(start_date) as start_date, MAX(end_date) as end_date
            FROM campaign_details
            GROUP BY campaign_id, campaign_name, communication_channel;
        """

        cursor.execute(QUERY)

        connection.commit()

        cursor.close()
        connection.close()

        return JSONResponse(content={"result": "Table created successfully"}, status_code=200)
    
    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error executing SQL query: {e}")


# Route to execute the create table SQL query
@app.get("/join_query/", dependencies=[Depends(JWTBearer())])
async def join_query(
    start_date: Optional[date] = Query(None, description="Start date for the query. For general users, the default is '2023-10-01'."),
    end_date: Optional[date] = Query(None, description="End date for the query. For general users, the default is '2023-10-30'."),
    role: str = Depends(get_user_role)
):
    try:
        connection = connect_to_mysql()
        if not connection:
            raise HTTPException(status_code=500, detail="Error connecting to the database")
        
        cursor = connection.cursor()
        
        if start_date is not None and end_date is not None and role == 'admin':
            QUERY = f"""
                SELECT cd.campaign_id, cd.campaign_name, cd.communication_channel, ct.campaign_type, ct.mobile_number,
                ct.campaign_date, ct.delivery
                FROM unique_campaign_details cd
                JOIN campaign_target ct ON cd.campaign_id = ct.campaign_id AND cd.communication_channel = ct.channel
                WHERE ct.campaign_date BETWEEN '{start_date}' AND '{end_date}' ORDER BY ct.campaign_date;
            """
        else:
            print("Else part is executed")
            QUERY = """
                SELECT cd.campaign_id, cd.campaign_name, cd.communication_channel, ct.campaign_type, ct.mobile_number,
                ct.campaign_date, ct.delivery
                FROM unique_campaign_details cd
                JOIN campaign_target ct ON cd.campaign_id = ct.campaign_id AND cd.communication_channel = ct.channel
                WHERE ct.campaign_date BETWEEN cd.start_date AND cd.end_date ORDER BY ct.campaign_date;
            """

        cursor.execute(QUERY)

        result = cursor.fetchall()

        converted_result = convert_dates_to_strings(result)

        connection.commit()

        cursor.close()
        connection.close()

        return JSONResponse(content={"result": converted_result}, status_code=200)

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error executing SQL query: {e}")
    

# Route to execute the create table SQL query
@app.get("/comm_via_channel/", dependencies=[Depends(JWTBearer())])
async def comm_via_channel(
    start_date: Optional[date] = Query(None, description="Start date for the query. For general users, the default is '2023-10-01'."),
    end_date: Optional[date] = Query(None, description="End date for the query. For general users, the default is '2023-10-30'."),
    role: str = Depends(get_user_role)
):
    try:
        connection = connect_to_mysql()
        if not connection:
            raise HTTPException(status_code=500, detail="Error connecting to the database")
        
        cursor = connection.cursor()
        
        role = get_user_role()
        print(role)
        if start_date is not None and end_date is not None and role == 'admin':
            QUERY = f"""
                SELECT cd.campaign_name, cd.communication_channel, COUNT(DISTINCT ct.mobile_number) AS total_customers_reached
                FROM unique_campaign_details cd
                JOIN campaign_target ct ON cd.campaign_id = ct.campaign_id AND cd.communication_channel = ct.channel
                WHERE ct.campaign_date BETWEEN '{start_date}' AND '{end_date}'
                GROUP BY cd.campaign_name, cd.communication_channel;
            """
        else:
            QUERY = """
                SELECT cd.campaign_name, cd.communication_channel, COUNT(DISTINCT ct.mobile_number) AS total_customers_reached
                FROM unique_campaign_details cd
                JOIN campaign_target ct ON cd.campaign_id = ct.campaign_id AND cd.communication_channel = ct.channel
                WHERE ct.campaign_date BETWEEN cd.start_date AND cd.end_date
                GROUP BY cd.campaign_name, cd.communication_channel;
            """

        cursor.execute(QUERY)

        result = cursor.fetchall()

        converted_result = convert_dates_to_strings(result)

        connection.commit()

        cursor.close()
        connection.close()

        return JSONResponse(content={"result": converted_result}, status_code=200)

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error executing SQL query: {e}")


# Route to execute the create table SQL query
@app.get("/comm_via_campaign_type/", dependencies=[Depends(JWTBearer())])
async def comm_via_campaign_type(
    start_date: Optional[date] = Query(None, description="Start date for the query. For general users, the default is '2023-10-01'."),
    end_date: Optional[date] = Query(None, description="End date for the query. For general users, the default is '2023-10-30'."),
    role: str = Depends(get_user_role)
):
    try:
        connection = connect_to_mysql()
        if not connection:
            raise HTTPException(status_code=500, detail="Error connecting to the database")
        
        cursor = connection.cursor()
        
        role = get_user_role()
        if start_date is not None and end_date is not None and role == 'admin':
            QUERY = f"""
                SELECT cd.campaign_name, ct.campaign_type, COUNT(DISTINCT ct.mobile_number) AS customer_count
                FROM unique_campaign_details cd
                JOIN campaign_target ct ON cd.campaign_id = ct.campaign_id AND cd.communication_channel = ct.channel
                WHERE ct.campaign_date BETWEEN '{start_date}' AND '{end_date}'
                GROUP BY cd.campaign_name, ct.campaign_type;
            """
        else:
            QUERY = """
                SELECT cd.campaign_name, ct.campaign_type, COUNT(DISTINCT ct.mobile_number) AS customer_count
                FROM unique_campaign_details cd
                JOIN campaign_target ct ON cd.campaign_id = ct.campaign_id AND cd.communication_channel = ct.channel
                WHERE ct.campaign_date BETWEEN cd.start_date AND cd.end_date
                GROUP BY cd.campaign_name, ct.campaign_type;
            """

        cursor.execute(QUERY)

        result = cursor.fetchall()

        converted_result = convert_dates_to_strings(result)

        connection.commit()

        cursor.close()
        connection.close()

        return JSONResponse(content={"result": converted_result}, status_code=200)

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error executing SQL query: {e}")