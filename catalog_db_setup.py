# Configuration

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
# Declare a Mapping
Base = declarative_base()


class User(Base):
    """Schema for User"""
    # Table
    __tablename__ = 'user'
    # Mapper
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(250))
    picture = Column(String(250))
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return 'User(id= %s, name= %s, email= %s)' % (
                    self.id, self.name, self.email)


class Catalog(Base):
    """Schema for Catalog"""
    # Table
    __tablename__ = 'catalog'
    # Mapper
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # Use this serialize function to be able to send JSON objects in a
    # serializable format
    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'created': self.time_created
        }


class Item(Base):
    """Schema for Item"""
    # Table
    __tablename__ = 'item'
    # Mapper
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    catalog_id = Column(Integer, ForeignKey('catalog.id'))
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    catalog = relationship(Catalog)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # Use this serialize function to be able to send JSON objects in a
    # serializable format
    @property
    def serialize(self):
        return {
            'description': self.description,
            'name': self.name,
            'id': self.id,
            'created': self.time_created
        }


# Configuration - Insert at end of file
engine = create_engine('sqlite:///catalogwithuser.db')
Base.metadata.create_all(engine)
