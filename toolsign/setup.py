from setuptools import setup, find_packages

setup(
    name='flask_app',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'flask',
        'flask_sqlalchemy',
        'sqlalchemy',
        'werkzeug',
        'functools',
        'flask_login',
        'jsonify',
        'datetime'
    ],
    entry_points={
        'console_scripts': [
            'flask_app=app:main'
        ]
    },
)

