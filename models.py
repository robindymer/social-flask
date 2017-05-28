import datetime

from flask_bcrypt import generate_password_hash
from flask_login import UserMixin
from peewee import *

DATABASE = SqliteDatabase('social.db')

class User(UserMixin, Model):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)
    
    class Meta:
        database = DATABASE # this model uses the 'social.db' database
        # the '-' orders by desc order for the joined_at column
        order_by = ('-joined_at',)
    
    # cls is so class can get passed into it and you can create 
    # the User model instance within the class
    # cls refers to the class the method belongs to
    @classmethod
    def create_user(cls, username, email, password, admin=False):
        try:
            # this ends up calling User.create on the model. Create a new instance (row)
            cls.create(
                username=username,
                email=email,
                password=generate_password_hash(password),
                is_admin=admin
            )
        # if the username or email is not unique
        except IntegrityError:
            raise ValueError("User already exists")


def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User], safe=True)
    DATABASE.close()