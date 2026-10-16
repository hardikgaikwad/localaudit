# =====================================================================
# WARNING: INTENTIONALLY INSECURE DEMO CODE FOR LOCALAUDIT. DO NOT USE.
# =====================================================================
import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from django.db import connection
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt

from .models import Product


def search(request):
    term = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM shop_product WHERE name LIKE '%{term}%'")
        rows = cursor.fetchall()
    return HttpResponse(str(rows))


def product_by_name(request):
    name = request.GET["name"]
    return Product.objects.raw("SELECT * FROM shop_product WHERE name = '%s'" % name)


@csrf_exempt
def import_cart(request):
    # Deserialises a cookie straight from the client.
    cart = pickle.loads(request.COOKIES["cart"].encode("latin1"))
    return HttpResponse(f"{len(cart)} items")


def load_config(request):
    config = yaml.load(request.body)
    return HttpResponse(str(config))


def calculator(request):
    expr = request.GET.get("expr", "1+1")
    return HttpResponse(str(eval(expr)))


def ping(request):
    host = request.GET.get("host", "localhost")
    os.system("ping -c 1 " + host)
    return HttpResponse("ok")


def disk_usage(request):
    # Constant command, no user input: a likely false positive for the LLM to spot.
    out = subprocess.check_output("df -h /", shell=True)
    return HttpResponse(out)


def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse(mark_safe("<h1>Hello " + name + "</h1>"))


def fetch_rates():
    return requests.get("https://rates.partner.test/api", verify=False).json()


def register(username, password):
    # TODO: security - switch to a real password hasher before launch
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return {"user": username, "hash": password_hash}
