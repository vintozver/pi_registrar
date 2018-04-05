#!/usr/bin/env python

from setuptools import setup

setup(
    name='pi_registrar',
    version='1.0',
    description='Registrar server and client for the hosts (similar to DDNS). \
Clients send https requests and update their addresses. \
Server receives the updates and consolidates them, also displays them. \
',
    author='Vitaly Greck',
    author_email='vintozver@ya.ru',
    url='https://www.python.org/sigs/distutils-sig/',
    packages=['pi_registrar'],
    install_requires=[
        'cherrypy', 'jinja2', 'gunicorn', 'pyasn1', 'cryptography',
    ],
    entry_points={
        'console_scripts': [
            'pi_registrar_server=pi_registrar.server:run',
            'pi_registrar_client=pi_registrar.client:run',
        ],
    },
)
