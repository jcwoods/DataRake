"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path, environ

here = path.abspath(path.dirname(__file__))
props = dict(line.strip().split('=') for line in open('project.properties'))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name=props['name'],

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=props['version'],

    description='Secrets scanning tool for use in or outside a pipeline',
    long_description=long_description,

    # The project's main homepage.
    url='http://github.com/jcwoods/datarake',

    # Author details
    author='Jeff Woods',
    author_email='jeff.c.woods@adp.com',

    # Choose your license
    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],

    python_requires='>=3.10',

    install_requires=[
        'pyyaml',
    ],

    keywords=['source', 'code', 'reporting', 'scanner', 'security', 'credentials', 'secrets' ],

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    # Ship the default config alongside the code so the CLI can locate it via
    # importlib.resources after install.
    package_data={
        'datarake': ['datarake.yaml'],
    },
    include_package_data=True,

    entry_points={
        'console_scripts': [
            'datarake=datarake.__main__:main',
        ],
    }
)
