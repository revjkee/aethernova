import os

# Make imports like `import backend.utils` resolve to the code in backend/src
# by adding the `backend/src` directory to this package's __path__.
this_dir = os.path.dirname(__file__)
src_path = os.path.join(this_dir, "src")
if os.path.isdir(src_path) and src_path not in __path__:
    __path__.insert(0, src_path)
