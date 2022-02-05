from website.app import create_app


app = create_app({
    'TESTING': True,
    'DEBUG': True,
    'SECRET_KEY': 'db8755b70f2cc6cceab244dde5022474ecf54d438f5a6d5c5bcc112f41853c7b',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
