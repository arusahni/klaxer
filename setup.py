"""Set up the package."""

import os
import re
import sys
from codecs import open as codecs_open
from setuptools import setup, find_packages

REQUIREMENTS = [
    'hug',
    'requests',
    'slacker',
    'zappa',
    'sqlalchemy',
    'psycopg2'
]

if sys.version_info <= (3, 6):
    sys.stderr.write('Python 3.6+ is required.' + os.linesep)
    sys.exit(1)

# Get the long description from the relevant file
with codecs_open('README.md', encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()

with open('klaxer/__init__.py', "r") as f:
    VERSION = re.search(r"^__version__\s*=\s*[\"']([^\"']*)[\"']", f.read(), re.MULTILINE).group(1)

setup(name='klaxer',
      version=VERSION,
      description='Restore sanity to your Slack service alerting',
      long_description=LONG_DESCRIPTION,
      classifiers=[
          'Development Status :: 1 - Pre-Alpha',
          'Environment :: Web Environment',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Framework :: Flask',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3 :: Only',
          'Topic :: Communications :: Chat',
      ],
      keywords='slack alerting alerts notifications debounce silence mute',
      author='Aru Sahni',
      author_email='arusahni@gmail.com',
      url='https://github.com/arusahni/klaxer',
      license='MIT',
      package_data={'': ['LICENSE']},
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=REQUIREMENTS,
      extras_require={
          'dev': ['pytest', 'coverage', 'pylint', 'pytest-cov'],
      },
     )
