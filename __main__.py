import sys
import os.path
from .driver import run

try:
    run()
except (KeyboardInterrupt, EOFError):
    print("Interrupted")
