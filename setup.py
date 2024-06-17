from setuptools import find_packages, setup
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

# See https://pytest-runner.readthedocs.io/en/latest/#conditional-requirement
needs_pytest = {"pytest", "test", "ptr"}.intersection(sys.argv)
pytest_runner = ["pytest-runner"] if needs_pytest else []

setup(
    name="propelauth-py",
    version="3.1.16",
    description="A python authentication library",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/propelauth/propelauth-py",
    packages=find_packages(include=["propelauth_py", "propelauth_py.*"]),
    author="PropelAuth",
    author_email="support@propelauth.com",
    license="MIT",
    install_requires=["pyjwt[crypto]>=2,<3", "requests"],
    setup_requires=pytest_runner,
    tests_require=["pytest==4.4.1"],
    test_suite="tests",
)
