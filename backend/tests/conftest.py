import os

os.environ.setdefault("SECRET_KEY", "test-key-0123456789abcdef0123456789abcdef")
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/surfacewatch-test-default.db")

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

from app.core.auth import password_hasher
from app.db.models import Base, User
from app.db.seed import seed_profiles


@pytest.fixture
def session_factory(tmp_path):
    postgres_url = os.getenv("TEST_DATABASE_URL")
    schema = "test_" + uuid.uuid4().hex
    if postgres_url:
        admin_engine = create_engine(postgres_url, connect_args={"prepare_threshold": None})
        with admin_engine.begin() as conn:
            conn.execute(CreateSchema(schema))
        engine = create_engine(
            postgres_url, connect_args={"prepare_threshold": None}
        ).execution_options(schema_translate_map={None: schema})
    else:
        engine = create_engine(
            f"sqlite:///{tmp_path}/test.db", connect_args={"check_same_thread": False}
        )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db:
        seed_profiles(db)
        db.add(User(username="admin", password_hash=password_hasher.hash("a-secure-test-password")))
        db.add(User(username="other", password_hash=password_hasher.hash("another-test-password")))
        db.commit()
    yield factory
    engine.dispose()
    if postgres_url:
        with admin_engine.begin() as conn:
            conn.execute(DropSchema(schema, cascade=True))
        admin_engine.dispose()


@pytest.fixture
def client(session_factory):
    from fastapi.testclient import TestClient

    from app.api.auth import attempts, global_attempts
    from app.db.session import get_db
    from app.main import app

    attempts.clear()
    global_attempts.clear()

    def override_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as c:
        c.headers["X-SurfaceWatch"] = "1"
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def logged_in(client):
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": "a-secure-test-password"}
        ).status_code
        == 200
    )
    return client
