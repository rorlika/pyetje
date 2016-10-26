from flask import Flask, render_template
from flask.ext.pagedown import PageDown
from flask.ext.bootstrap import Bootstrap
from flask_bootstrap import WebCDN
from flask.ext.mail import Mail
from flask.ext.moment import Moment
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from config import config


login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()

def create_app(config_name):
	app = Flask(__name__)
	app.config.from_object(config[config_name])
	config[config_name].init_app(app)
	bootstrap.init_app(app)
	mail.init_app(app)
	moment.init_app(app)
	pagedown.init_app(app)
	
	login_manager.init_app(app)
	if not app.debug and not app.testing and not app.config['SSL_DISABLE']:
		from flask.ext.sslify import SSLify
		sslify = SSLify(app)
	from main import main as main_blueprint
	app.register_blueprint(main_blueprint)
	from auth import auth as auth_blueprint
	app.register_blueprint(auth_blueprint,url_prefix='/auth')

	db.init_app(app)

	return app