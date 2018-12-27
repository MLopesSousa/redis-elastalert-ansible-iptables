from flask import Flask
from lark.ext.flask.redis_api import redis_api_blueprint
from lark.ext.flask.flask_redis import Redis

app = Flask(__name__)
# Add a simple redis connection to the global object
Redis(app)

app.config['DEFAULT_LARK_SCOPES'] = set(['admin'])

# Mount the redis blueprint
app.register_blueprint(redis_api_blueprint, url_prefix='/api/0')


if __name__ == '__main__':
    app.run(host="0.0.0.0")

