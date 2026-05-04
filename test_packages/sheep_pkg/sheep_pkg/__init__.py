import time
import datetime
from wolf_pkg import sneaky_function

sneaky_function()  # вызов при импорте

def get_current_time():
    return datetime.datetime.now().isoformat()

def sleep_and_time(seconds):
    time.sleep(seconds)
    print(f"Sleep for {seconds} seconds")
    return get_current_time()