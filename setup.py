from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vigilante",
    version="1.0.0",
    author_email="aljawharakqs@gmail.com",
    description="A CLI tool for intrusion detection using computational intelligence artificial immune system algorithms.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AljawharaK/vigilante",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vigilante=intrusion_detection.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        'intrusion_detection': ['*.env.example'],
    },
    keywords=[
        "security",
        "intrusion-detection",
        "ai",
        "machine-learning",
        "cybersecurity",
        "cli",
        "anomaly-detection"
    ],
    project_urls={
        "Source": "https://github.com/AljawharaK/vigilante",
    },
)