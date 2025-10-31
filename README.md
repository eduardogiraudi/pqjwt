# PQJWT — Post-Quantum JWT Libraries (Python & JavaScript)

**PQJWT** is an open-source project providing **post-quantum** implementations of the **JSON Web Token (JWT)** protocol in **Python** and **JavaScript**.  
The goal is to enable JWT signing and verification that remain secure in the quantum era, based on the **ML-DSA (Dilithium)**, **Falcon**, and **SPHINCS+** algorithms standardized by NIST PQC.

---

## Repository Structure

```
pqjwt-monorepo/
│
├── python/       → Python library (PyPI)
│   └── README.md
│
├── js/           → JavaScript library (npm)
│   └── README.md
│
├── tools/        → Common build/test/lint scripts
│
├── LICENSE       → MIT License for the entire project
└── README.md     → This file
```

---

## Libraries

### [Python Library (`pqjwt`)](./python/README.md)

Python implementation providing key management, JWT creation, signing, and verification with complete claim validation.  
Supports:
- ML-DSA (Dilithium)
- Falcon (padded)
- SPHINCS+ (SHA2 / SHAKE variants)

> See the [full Python documentation](./python/README.md)

---

### [JavaScript Library (`pqjwt-js`)](./js/README.md)

JavaScript implementation for **Node.js** and browsers, designed to interoperate with the Python version.  
It allows JWT creation and verification using the same post-quantum signature algorithms and key formats.

> 📖 See the [full JavaScript documentation](./js/README.md)

---


## Project Goal

PQJWT aims to provide a **cross-language, quantum-safe JWT foundation**, maintaining compatibility with existing web standards (RFC 7519) while preparing for next-generation cryptographic security.

---

## License

This project is released under the **MIT License**.  
See the [LICENSE](./LICENSE) file for details.  
Each sub-library (Python and JavaScript) references the same license in its respective `README.md`.

---

## Contributing

Pull requests are welcome.  
Ensure all code follows project conventions and passes tests before submitting a PR.

---

## Contact

Authors: **PQJWT Contributors**  
Email: `eduardogiraudi000@gmail.com`  
Repository: [https://github.com/your-username/pqjwt](https://github.com/eduardogiraudi/pqjwt)