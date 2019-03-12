import os

from setuptools import setup

from intezer_sdk import SDK_VERSION

this_dir = os.path.dirname(__file__)
requirements_filename = os.path.join(this_dir, 'requirements.txt')

with open(requirements_filename) as f:
    PACKAGE_INSTALL_REQUIRES = [line[:-1] for line in f]

setup(
    name='intezersdk',
    version=SDK_VERSION,
    packages=['intezer_sdk'],
    url='',
    license='',
    author='Intezer',
    author_email='info@intezer.com',
    description='Intezer SDK',
    install_requires=PACKAGE_INSTALL_REQUIRES
)
