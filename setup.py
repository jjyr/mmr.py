import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mmr.py",
    version="0.0.4",
    author="jjy",
    author_email="jjyruby@gmail.com",
    test_suite="tests",
    description="Merkle Mountain Range in python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jjyr/mmr.py",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
