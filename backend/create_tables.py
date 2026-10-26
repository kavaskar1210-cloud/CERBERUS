from database import Base, engine
from models.scan import Scan
from models.user import User


print("Creating database tables...")

Base.metadata.create_all(bind=engine)

print("Database tables created successfully.")