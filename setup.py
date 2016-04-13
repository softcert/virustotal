from setuptools import setup, find_packages


setup(
    name="virustotal",
    version="0.0.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "virustotal=virustotal:main"
        ]
    }
)
