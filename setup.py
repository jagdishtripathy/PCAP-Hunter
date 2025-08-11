from setuptools import setup, find_packages

setup(
    name="PCAP Hunter",
    version="1.0.0",
    author="Jagadish Tripathy",
    author_email="you@example.com",
    description="Automated tool to detect and extract CTF flags from PCAP files",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/jagdishtripathy/PCAP-Hunter",
    packages=find_packages(),
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "pcap-hunter=main:main"
        ]
    },
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    keywords="PCAP CTF flags security analysis",
)
