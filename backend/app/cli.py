import argparse
import getpass

from sqlalchemy import select

from app.core.auth import password_hasher
from app.db.models import User
from app.db.seed import seed_profiles
from app.db.session import SessionLocal


def main():
    parser = argparse.ArgumentParser(description="SurfaceWatch local administration")
    parser.add_argument("command", choices=["create-user", "reset-password", "seed"])
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    with SessionLocal() as db:
        seed_profiles(db)
        if args.command == "seed":
            return
        user = db.scalar(select(User).where(User.username == args.username))
        if not args.username.strip() or len(args.username) > 80:
            parser.error("Username must contain 1–80 characters")
        if args.command == "create-user" and user:
            parser.error("User already exists")
        if args.command == "reset-password" and not user:
            parser.error("User does not exist")
        password = getpass.getpass("Password (12–256 characters): ")
        if len(password) < 12 or len(password) > 256:
            parser.error("Password must contain 12–256 characters")
        if password != getpass.getpass("Confirm password: "):
            parser.error("Passwords do not match")
        hashed = password_hasher.hash(password)
        if user:
            user.password_hash = hashed
            from app.db.models import AuthSession

            for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id)):
                db.delete(s)
        else:
            db.add(User(username=args.username, password_hash=hashed))
        db.commit()
        print("User saved.")


if __name__ == "__main__":
    main()
