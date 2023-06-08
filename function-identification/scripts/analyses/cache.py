import os
try:
    import cPickle as pickle
except ImportError:
    import pickle

from functools import wraps

import idc

# TODO: Implement a way to delete caches
# + Maybe expiration?


class Cache(object):
    def __init__(self):
        self.root_dir = os.path.join(os.path.dirname(idc.get_idb_path()), "cache")
        os.makedirs(self.root_dir, exist_ok=True)

    def cache(self, name):
        cache_file = os.path.join(self.root_dir, name + '.pkl')

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if os.path.exists(cache_file):
                    with open(cache_file, "rb") as f:
                        return pickle.loads(f.read())
                else:
                    res = func(*args, **kwargs)
                    with open(cache_file, "wb") as f:
                        f.write(pickle.dumps(res))
                    return res
            return wrapper
        return decorator

cache = Cache()