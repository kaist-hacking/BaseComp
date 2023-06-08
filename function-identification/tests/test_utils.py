import sys
import os
from functools import wraps

import idc

ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(ROOT, '../ida_script'))

def sandbox(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout = open('stdout.txt', 'w', encoding='utf-8')
        sys.stderr = open('stderr.txt', 'w', encoding='utf-8')

        try:
            func(*args, **kwargs)
        except: # pylint: disable=bare-except
            import traceback
            sys.stderr.write(traceback.format_exc())
            idc.qexit(0)

        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
    return wrapper

def get_binary(rel_path):
    return os.path.join(ROOT, "samples", rel_path)
