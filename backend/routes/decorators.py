"""
JWT authentication decorator and role-based access helpers.
"""
import jwt
from functools import wraps
from flask import request, jsonify, current_app, g
from models import User, ActivityLog
from extensions import db


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Authorization token required'}), 401
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(payload['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 404
            if user.status != 'active':
                return jsonify({'error': 'Account not active'}), 403
            g.current_user = user
            g.current_user_id = user.id
            g.current_role = user.role
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            if g.current_role not in roles:
                return jsonify({'error': f'Access denied. Required roles: {list(roles)}'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def log_activity(user_id: int, action: str, resource: str = None, resource_id: int = None):
    try:
        log = ActivityLog(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
