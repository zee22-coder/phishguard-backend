from flask import Flask

def create_app():
    app = Flask(__name__)

    from app.scanner import scanner_bp
    app.register_blueprint(scanner_bp)
    return app

    