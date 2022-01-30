from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, Boolean, create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class Attack(Base):
    __tablename__ = "Attack"

    id = Column(Integer, primary_key=True)
    successful = Column(Boolean, nullable=False)
    ip = Column(String, nullable=False)
    service = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    login = Column(String, nullable=False)
    password = Column(String, nullable=True)
    total_tries = Column(Integer, nullable=False)


def init_database():
    engine = create_engine('sqlite:///attacks.db', echo=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    return session
