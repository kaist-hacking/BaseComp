import os
import subprocess
import sys
import shutil
import multiprocessing
import platform

# Build vex

CWD = os.path.dirname(os.path.realpath(__file__))
VEX_PATH = os.path.abspath(os.path.join(CWD, 'vex'))

assert len(os.listdir(VEX_PATH)) != 0, "error"

e = os.environ.copy()
e['MULTIARCH'] = '1'
e['DEBUG'] = '1'

if sys.platform == 'win32':
    cmd = ['nmake', '/f', 'Makefile-msvc', 'all']
elif shutil.which('gmake') is not None:
    cmd = ['gmake', '-f', 'Makefile-gcc', '-j', str(multiprocessing.cpu_count()), 'all']
else:
    cmd = ['make', '-f', 'Makefile-gcc', '-j', str(multiprocessing.cpu_count()), 'all']

try:
    subprocess.run(cmd, cwd=VEX_PATH, env=e, check=True)
except FileNotFoundError:
    print("Couldn't find " + cmd[0] + " in PATH")
    raise
except subprocess.CalledProcessError as err:
    print("Error while building libvex: " + str(err))
    raise

# Build pyvex_c

PYVEX_C_PATH = os.path.abspath(os.path.join(CWD, 'pyvex_c'))

e = os.environ.copy()
e['VEX_LIB_PATH'] = VEX_PATH
e['VEX_INCLUDE_PATH'] = os.path.join(VEX_PATH, 'pub')
e['VEX_LIB_FILE'] = os.path.join(VEX_PATH, 'libvex.lib')

if sys.platform == 'win32':
    cmd = ['nmake', '/f', 'Makefile-msvc']
elif shutil.which('gmake') is not None:
    cmd = ['gmake', '-f', 'Makefile', '-j', str(multiprocessing.cpu_count())]
else:
    cmd = ['make', '-f', 'Makefile', '-j', str(multiprocessing.cpu_count())]

try:
    subprocess.run(cmd, cwd=PYVEX_C_PATH, env=e, check=True)
except FileNotFoundError:
    print("Couldn't find " + cmd[0] + " in PATH")
    raise
except subprocess.CalledProcessError as err:
    print("Error while building libvex: " + str(err))
    raise