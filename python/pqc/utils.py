import os
import sys

if os.name == 'nt':
    library = 'pqc_shared.dll'
elif sys.platform == 'darwin':
    library = 'libpqc_shared.dylib'
else:
    library = 'libpqc_shared.so'
