"""
Test fixture for rules/python/missing-authorization.yaml

Lines annotated "ruleid" must produce the named finding.
Lines annotated "ok" must NOT produce it.
"""

from flask import Flask, request
from flask_jwt_extended import jwt_required
from flask_login import current_user, login_required
from django.views.decorators.csrf import csrf_exempt

app = Flask(__name__)


class Order:
    query = None
    objects = None


class Account:
    query = None


# ---------------------------------------------------------------- vulnerable

# ruleid: flask-route-missing-auth-decorator
@app.route("/orders/<order_id>")
def get_order(order_id):
    return {"id": order_id}


# ruleid: flask-route-missing-auth-decorator
@app.route("/admin/users", methods=["GET"])
def list_users():
    return {"users": []}


@app.route("/orders/<order_id>/detail")
@login_required
def order_detail(order_id):
    # ruleid: query-by-id-without-ownership-check
    order = Order.query.get(order_id)
    return {"order": order}


@app.route("/accounts/<account_id>")
@login_required
def account_detail(account_id):
    # ruleid: query-by-id-without-ownership-check
    account = Account.query.get_or_404(account_id)
    return {"account": account}


# ruleid: django-view-csrf-exempt
@csrf_exempt
def webhook_receiver(request):
    return {"ok": True}


# --------------------------------------------------------------------- safe

@app.route("/me/orders")
@login_required
def my_orders():
    # ok: query-by-id-without-ownership-check
    return {"orders": Order.query.filter_by(user_id=current_user.id).all()}


@app.route("/orders/<order_id>/secure")
@jwt_required()
def secure_order(order_id):
    # ok: query-by-id-without-ownership-check
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    return {"order": order}


# ok: flask-route-missing-auth-decorator
@app.route("/health")
@login_required
def health():
    return {"status": "ok"}
