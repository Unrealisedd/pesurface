from setuptools import setup, find_packages

setup(
    name="pesurface",
    version="0.1.0",
    description="PE Attack Surface Mapper — find LPE primitives in Windows binaries",
    author="Unrealisedd",
    url="https://github.com/Unrealisedd/pesurface",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pefile>=2023.2.7",
    ],
    extras_require={
        "disasm": ["capstone>=5.0.0"],
    },
    entry_points={
        "console_scripts": [
            "pesurface=pesurface.__main__:main",
        ],
    },
    classifiers=[
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Environment :: Console",
    ],
)
