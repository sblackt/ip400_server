from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="ip400-server",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="IP400 Server for processing and displaying APRS and other radio packet data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ip400-server",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'ip400-server=ip400_server.ip400_server:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    install_requires=[
        'flask>=2.0.0',
        'pyserial>=3.5',
    ],
    include_package_data=True,
)
