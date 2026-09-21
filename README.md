# OWASPScan

OWASPScan is a lightweight, external web security misconfiguration scanner developed as part of a research internship project. It analyzes publicly accessible security configurations and produces OWASP-aligned technical findings, risk scores, confidence levels, and AI-assisted recommendations.

## Implemented Checks

OWASPScan currently includes:

* HTTP security-header analysis
* TLS certificate checks
* CORS configuration checks
* Rate-limiting observations
* Sensitive-path exposure detection
* Object-path discovery
* Technology and software-version disclosure checks
* Deterministic risk and confidence scoring
* OWASP-aligned terminal reporting
* AI-assisted explanations and recommendations using Gemma

## Project Structure

OWASPScan contains:

* `main.py`: Runs the complete scan workflow.
* `scanner/`: Contains the individual security checks.
* `engine/`: Contains the deterministic risk-scoring logic.
* `reports/`: Generates the technical and AI-assisted reports.
* `wordlists/`: Contains the sensitive-path and object-path wordlists.
* `requirements.txt`: Lists the required Python packages.
* `.gitignore`: Excludes temporary and unnecessary files.
* `README.md`: Provides project documentation.

## Installation

Clone or download the project and open its main directory.

Create a virtual environment:

`python3 -m venv venv`

Activate it on macOS or Linux:

`source venv/bin/activate`

Install the required packages:

`pip install -r requirements.txt`

## Usage

Run the scanner using:

`python3 main.py`

Enter the target domain when requested, for example:

`example.com`

OWASPScan validates the target, executes the enabled security checks, calculates the risk summary, and displays the final terminal report.

## AI Reporting Setup

The technical scanner can operate without the AI-reporting component. AI-assisted reporting requires Ollama and the configured Gemma model.

The project currently expects:

* Ollama API: `http://localhost:11434`
* Model: `gemma3:4b`

Start Ollama using:

`ollama serve`

Install the Gemma model when necessary:

`ollama pull gemma3:4b`

## OWASP Alignment

Findings are mapped to relevant OWASP API Security Top 10 categories, including:

* OWASP API1:2023 – Broken Object Level Authorization
* OWASP API4:2023 – Unrestricted Resource Consumption
* OWASP API8:2023 – Security Misconfiguration

The OWASP mapping identifies the security category related to each observation. It does not confirm that exploitation occurred.

## Technology Disclosure

The technology-disclosure checker passively inspects selected HTTP response headers and HTML metadata, including:

* `Server`
* `X-Powered-By`
* `X-AspNet-Version`
* `X-AspNetMvc-Version`
* `X-Generator`
* HTML generator meta tags

A disclosed product or version is treated as a technology-fingerprinting observation. OWASPScan does not automatically associate disclosed versions with CVEs, NVD records, exploits, or confirmed vulnerabilities.

## Risk and Confidence

OWASPScan uses the following risk levels:

* Critical
* High
* Medium
* Low
* Informational

It also uses confidence levels to communicate how strongly the external evidence supports a finding:

* Confirmed
* Likely
* Possible
* Uncertain

A high-confidence finding does not necessarily confirm exploitability.

## Limitations

OWASPScan:

* Performs external and non-destructive testing only.
* Does not review source code or private server configurations.
* Does not perform authenticated penetration testing.
* Does not confirm exploitability.
* Does not confirm BOLA or IDOR from object-path discovery alone.
* Does not verify whether disclosed software versions contain known vulnerabilities.
* May be affected by redirects, CDNs, WAFs, proxies, authentication, and custom error pages.
* Uses a limited number of requests when observing rate-limiting behavior.

## Responsible Use

OWASPScan must only be used against systems that the user owns or is explicitly authorized to assess.

Sensitive-path and object-path checks should be performed only in controlled and authorized environments.

## Academic Context

OWASPScan was designed and implemented as a lightweight and uncertainty-aware web security misconfiguration scanner during a research internship project.

**Author:** Maria Doukkali
**Institution:** Al Akhawayn University in Ifrane
**Field:** Computer Science and Cybersecurity
