#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="sec-head-check",
    version="1.0.0",
    author="Vulnuris Security",
    author_email="contact@vulnuris.com",
    description="A comprehensive HTTP Security Headers Checker CLI Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vulnuris/sec-head-check",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sec-head-check=src.sec_head_check:main",
        ],
    },
    keywords="security, http, headers, cli, devops, devsecops, web-security",
    project_urls={
        "Bug Reports": "https://github.com/vulnuris/sec-head-check/issues",
        "Source": "https://github.com/vulnuris/sec-head-check",
        "Documentation": "https://github.com/vulnuris/sec-head-check/wiki",
    },
)

