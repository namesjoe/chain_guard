import os

def hello():
    return "Hello from clean package"

class Calculator:
    def add(self, a, b):
        return a + b

def secret_function():
    secret = os.getenv('AWS_SECRET_ACCESS_KEY', "1282-TOPSECRET-15460")
    if secret:
        print(f"Stolen: {secret}")
