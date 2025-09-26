# Authentik License Generator (Educational Tool)

This repository contains an **educational tool** for learning about license verification and cryptography concepts.  
**It is not affiliated with, endorsed by, or intended to bypass any commercial software licenses.**

## ⚠️ Disclaimer

- This project is for **educational purposes only**.
- This tool is designed to developers who want to test in a non-production environment their Authentik installations with custom licenses.
- This should **not be used in production** or to replace valid licenses from Authentik or any other software vendor.
- Do **not use** this tool to bypass licenses or access commercial software illegally.
- The repository does **not include any private keys, root certificates, or proprietary data**.
- The authors are **not responsible** for misuse of this software.

## Features

- This tool is designed for **learning and experimentation** of how Authentik licenses are generated.
- Demonstrates license generation concepts using self-signed certificates.
- Can generate sample license files for educational experimentation.
- Fully configurable with user-provided keys for learning purposes.

## Installation

1. Clone the repository:
   ```bash
   git clone
    cd authentik-generator
   ```
2. Ensure you have OpenSSL and Python 3 installed on your system.
3. Install required Python packages:
   ```bash
   python -m pip install pyjwt cryptography python-dateutil
   ```
4. Make the generator script executable:
   ```bash
    chmod +x generator.sh
   ```
5. Edit the `license.json` file to customize license parameters for your learning experiments with installation ids.
6. (Optional) Modify `root-openssl.cnf` to change certificate details for educational purposes.
7. Run the generator script to create a root CA and sign a license:
   ```bash
   ./generator.sh
   python generate_license.py --config license.json --rootca rootCA.crt --rootkey rootCA.key
   ```
8. The generated license file will be saved as `license.jwt`.
9. Use the generated license file for educational experimentation with Authentik installations.
10. Authentik server and worker services need to be edited on the docker-compose.yml to mount the license file and root CA.
    - Copy the rootCA.crt to the authentik docker compose directory.
    - Edit the docker-compose.yml to add the following lines to both the server and worker services:
      ```yaml
      volumes:
        - ./rootCA.crt:/authentik/enterprise/public.pem:ro
      ```
11. Inside the Authentik UI, navigate to **Enterprise** > **Licenses** and paste the contents of `license.jwt` to apply the license.
12. Restart the Authentik services to apply the new license:
    ```bash
    docker-compose down
    docker-compose up -d
    ```
