import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='cidemiasecurity',
    version='0.0.1',
    description='A python package to centralize everything security for Cidemia projects',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/cidemia/cidemia-security',
    license='MIT',
    author='Mouhamad Ndiankho THIAM',
    author_email='thiamouhamadpro@gmail.com',
    packages=setuptools.find_packages(),
    install_requires=[
        "pydantic",
        "python-dotenv",
        "fastapi",
        "pyjwt",
        "passlib[bcrypt]",
        "py_eureka_client",
        "requests",
        "PyYAML",
        "werkzeug",
    ],
    test_suite='nose.collector',
    tests_require=['nose'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
