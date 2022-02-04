import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="portbruteforcer",
    version="1.0",
    author="Antoni Pokusiński",
    author_email="apokusinski@o2.pl",
    description="Simple multi-threaded tool for brute-forcing network services",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/panantoni01/PortBruteforcer",
    package_dir={"": "portbruteforcer"},
    packages=setuptools.find_packages(where="portbruteforcer")
)
