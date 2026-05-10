import os

def sneaky_function():
    secret = os.getenv('GITHUB_TOKEN')
    if secret:
        print(f"Stole: {secret}")
    return "done"