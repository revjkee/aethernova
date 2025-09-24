# hr_ai/tests/test_db_models.py

import pytest
from sqlalchemy.exc import IntegrityError
from hr_ai.database.models import User, Resume, Skill, AuditLog, Base
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture(scope="module")
def db_engine():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="function")
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(bind=connection)
    session = SessionLocal()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


def test_user_model_creation(db_session: Session):
    user = User(username="jdoe", email="jdoe@example.com", hashed_password="x123")
    db_session.add(user)
    db_session.commit()
    fetched = db_session.query(User).filter_by(username="jdoe").first()
    assert fetched is not None
    assert fetched.email == "jdoe@example.com"


def test_resume_association(db_session: Session):
    user = User(username="alice", email="alice@example.com", hashed_password="pass")
    resume = Resume(content="Full resume text", user=user)
    db_session.add_all([user, resume])
    db_session.commit()
    fetched_resume = db_session.query(Resume).filter_by(user_id=user.id).first()
    assert fetched_resume is not None
    assert fetched_resume.user.username == "alice"


def test_skill_linkage(db_session: Session):
    skill = Skill(name="Machine Learning")
    db_session.add(skill)
    db_session.commit()
    retrieved = db_session.query(Skill).filter_by(name="Machine Learning").first()
    assert retrieved is not None
    assert retrieved.name == "Machine Learning"


def test_unique_constraint_on_email(db_session: Session):
    user1 = User(username="bob", email="bob@example.com", hashed_password="abc")
    user2 = User(username="bobby", email="bob@example.com", hashed_password="def")
    db_session.add(user1)
    db_session.commit()
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        db_session.commit()
        db_session.rollback()


def test_audit_log_entry(db_session: Session):
    entry = AuditLog(action="create", entity="user", performed_by="system")
    db_session.add(entry)
    db_session.commit()
    log = db_session.query(AuditLog).filter_by(entity="user").first()
    assert log.action == "create"
    assert log.performed_by == "system"


def test_model_null_constraints(db_session: Session):
    incomplete_user = User(username=None, email="nulltest@example.com", hashed_password="pwd")
    db_session.add(incomplete_user)
    with pytest.raises(IntegrityError):
        db_session.commit()
        db_session.rollback()
