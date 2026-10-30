
import asyncio
import os
import getpass

from datetime import datetime, timezone
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from argon2 import PasswordHasher
from pymongo.errors import DuplicateKeyError


load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "invoice_verification")

password_hasher = PasswordHasher()


async def create_admin():
    if not MONGODB_URI:
        print("ERROR: MONGODB_URI is missing from your .env file.")
        return

    email = input("Enter admin email: ").strip().lower()

    if not email or "@" not in email:
        print("ERROR: Enter a valid email address.")
        return

    password = getpass.getpass("Enter admin password: ")
    confirm_password = getpass.getpass("Confirm admin password: ")

    if password != confirm_password:
        print("ERROR: Passwords do not match.")
        return

    if len(password) < 6:
        print("ERROR: Password must contain at least 6 characters.")
        return

    client = AsyncIOMotorClient(MONGODB_URI, tz_aware=True)

    try:
        await client.admin.command("ping")
        print("MongoDB connection successful.")

        db = client[MONGODB_DB]
        users = db["users"]

        await users.create_index("email", unique=True)

        existing_admin = await users.find_one({"role": "admin"})

        if existing_admin:
            print("An admin account already exists.")
            print("No additional admin account was created.")
            return

        admin = {
            "email": email,
            "password_hash": password_hasher.hash(password),
            "role": "admin",
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }

        await users.insert_one(admin)

        print("\nSUCCESS: Admin account created.")
        print("Email:", email)
        print("Password: securely hashed using Argon2.")

    except DuplicateKeyError:
        print("ERROR: This email address already exists.")

    except Exception as error:
        print("ERROR:", str(error))

    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(create_admin())
