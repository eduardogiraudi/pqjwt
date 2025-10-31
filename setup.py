from setuptools import setup, find_packages
import os

# Leggi il contenuto di README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Leggi i requisiti
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Ottieni la versione dal pacchetto
about = {}
with open(os.path.join("pqjwt", "__init__.py"), "r", encoding="utf-8") as f:
    exec(f.read(), about)

setup(
    name="pqjwt",
    version=about["__version__"],
    packages=find_packages(),
    install_requires=requirements,
    
    # Metadati
    author=about["__author__"],
    author_email=about["__email__"],
    description=about["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/pqjwt",
    
    # Classificatori
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    
    # Parole chiave
    keywords="jwt, post-quantum, cryptography, security, authentication, ml-dsa, dilithium, falcon, sphincs",
    
    # Requisiti Python
    python_requires=">=3.7",
    
    # Dati aggiuntivi
    include_package_data=True,
    zip_safe=False,
    
    # Entry points (opzionale per futuri comandi CLI)
    # entry_points={
    #     'console_scripts': [
    #         'pqjwt=pqjwt.cli:main',
    #     ],
    # },
)