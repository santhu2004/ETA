#!/usr/bin/env python3
"""
Setup script for Encrypted Traffic Analysis System
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="encrypted-traffic-analysis",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced encrypted traffic analysis and threat detection system",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/encrypted-traffic-analysis",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/encrypted-traffic-analysis/issues",
        "Source": "https://github.com/yourusername/encrypted-traffic-analysis",
        "Documentation": "https://github.com/yourusername/encrypted-traffic-analysis#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "test": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "encrypted-traffic-analysis=cli.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="security, network, traffic, analysis, threat-detection, tls, encryption",
)
