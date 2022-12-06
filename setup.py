import os

from setuptools import setup


def rel(*xs):
    return os.path.join(os.path.abspath(os.path.dirname(__file__)), *xs)


with open(rel('intezer_sdk', '__init__.py'), 'r') as f:
    version_marker = '__version__ = '
    for line in f:
        if line.startswith(version_marker):
            _, version = line.split(version_marker)
            version = version.strip().strip("'")
            break
    else:
        raise RuntimeError('Version marker not found.')

with open('README.md') as f:
    long_description = f.read()

install_requires = [
    'requests >= 2.22.0,<3'
]
setup(
    name='intezer_sdk',
    version=version,
    packages=['intezer_sdk'],
    url='https://github.com/intezer/analyze-python-sdk',
    license='Apache License v2',
    author='Intezer Labs ltd.',
    author_email='info@intezer.com',
    description='Intezer Analyze SDK',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=install_requires,
    keywords='intezer',
    tests_requires=[
        'responses == 0.16.0',
        'pytest == 6.2.5'
    ],
    python_requires='!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,!=3.5.*',
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11']
)
