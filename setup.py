from setuptools import setup, find_packages

setup(
    name="netslicer",
    version="1.0.0",
    author="Ruhiyatna Rahman",
    author_email="rruhiyatna@example.com",
    description="A network monitoring and security tool with GUI interface",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/MrRahman20/netslicer",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "netslicer": ["*.ico"],
    },
    install_requires=[
        "scapy>=2.4.5",
        "wxPython>=4.1.1",
        "python-nmap>=0.7.1",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "netslicer=netslicer.app:main",
        ],
    },
)