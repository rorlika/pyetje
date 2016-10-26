import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    	SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    	OAUTH_CREDENTIALS = {
				    'facebook': {
				        'id': '1284235241610332',
				        'secret': '82425e1550113806228601c1eeb76267'
				    },
				    'twitter': {
				        'id': '3RzWQclolxWZIMq5LJqzRZPTl',
				        'secret': 'm9TEd58DSEtRrZHpz2EjrV9AhsBRxKMo8m3kuIZj3zLwzwIimt'
				    }
				}
    	MAIL_SERVER = 'smtp.googlemail.com'
    	MAIL_PORT = 587
    	MAIL_USE_TLS = True
    	MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    	MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    	FLASKY_MAIL_SUBJECT_PREFIX = '[LikaThon]'
    	FLASKY_MAIL_SENDER = 'Lika Admin <lika@contact.com>'
    	FLASKY_ADMIN = os.environ.get('Lika_ADMIN')
    	FLASKY_POSTS_PER_PAGE = 10
    	FLASKY_FOLLOWERS_PER_PAGE = 50
    	FLASKY_COMMENTS_PER_PAGE = 10
    	FLASKY_SLOW_DB_QUERY_TIME=0.5
    	SSL_DISABLE = True

	@staticmethod
	def init_app(app):
		pass

class DevelopmentConfig(Config):
	DEBUG = True
	SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'data-pymv.sqlite')

class TestingConfig(Config):
	TESTING = True
	SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')

class ProductionConfig(Config):
	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'data.sqlite')
	@classmethod
	def init_app(cls, app):
		Config.init_app(app)
		# email errors to the administrators
		import logging
		from logging.handlers import SMTPHandler
		credentials = None
		secure = None
		if getattr(cls, 'MAIL_USERNAME', None) is not None:
			credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
			if getattr(cls, 'MAIL_USE_TLS', None):
				secure = ()
		mail_handler = SMTPHandler(
			mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
			fromaddr=cls.FLASKY_MAIL_SENDER,
			toaddrs=[cls.FLASKY_ADMIN],
			subject=cls.FLASKY_MAIL_SUBJECT_PREFIX + ' Application Error',
			credentials=credentials,
			secure=secure)
		mail_handler.setLevel(logging.ERROR)
		app.logger.addHandler(mail_handler)

class HerokuConfig(ProductionConfig):
	@classmethod
	def init_app(cls, app):
		ProductionConfig.init_app(app)
		SSL_DISABLE = bool(os.environ.get('SSL_DISABLE'))
		# log to stderr
		from werkzeug.contrib.fixers import ProxyFix
		app.wsgi_app = ProxyFix(app.wsgi_app)
		import logging
		from logging import StreamHandler
		file_handler = StreamHandler()
		file_handler.setLevel(logging.WARNING)
		app.logger.addHandler(file_handler)

config = {
	'development': DevelopmentConfig,
	'testing': TestingConfig,
	'production': ProductionConfig,
	'default': DevelopmentConfig
}
