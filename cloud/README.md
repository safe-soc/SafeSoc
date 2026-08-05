# 🛡️ CloudLens: AWS IAM Risk & Attack Path Analyzer

**CloudLens** is a Local and self-hosted security intelligence platform designed to analyze AWS IAM configurations, detect dangerous misconfigurations, and visualize privilege-escalation attack paths. 

Unlike standard auditing tools that provide static lists, CloudLens builds a dynamic, force-directed relationship map of your cloud identity infrastructure, allowing security engineers to see exactly how an attacker could move laterally through an account.

---

## 🌟 Core Capabilities

### 🔍 **Automated IAM Security Auditing**
Performs deep, programmatic analysis of IAM Users, Roles, and Policies using the AWS SDK (Boto3) to uncover hidden privileges, misconfigurations, and dangerous permission chains.

### 🗺️ **Intelligent Attack Path Mapping**
Visualizes trust relationships and privilege escalation paths using a dynamic graph engine, highlighting potential “blast radius” risks and high-impact identities.

### ⚖️ **Real-Time Weighted Risk Scoring**
Generates a comprehensive security score (**0–100**) based on severity-weighted findings across Critical, High, and Medium vulnerabilities, enabling clear prioritization of remediation efforts.

### 🚨 **Instant Security Notifications (Telegram Integration)**
Sends structured, readable, and actionable security summaries directly to Telegram upon scan completion—ensuring rapid awareness and response capability.

### 🔒 **Privacy-First, Zero-Cloud Dependency**
Fully self-hosted by design. All processing happens locally, ensuring AWS credentials and IAM data never leave your environment.

---


## 🖼️ Visual Showcase

<div align="center">
  <p><b>Main Security Dashboard</b></p>
  <img src="./assets/iam2.png" width="900" alt="CloudLens Security Dashboard">
  <br><br>
  <p><b>Interactive Attack Path Graph</b></p>
  <img src="./assets/iam1.png" width="900" alt="IAM Attack Path Graph">
  <br><br>
  <p><b>Risk Findings Overview</b></p>
  <img src="./assets/iam3.png" width="900" alt="Risk Findings Summary Dashboard">
  <br><br>
  <p><b>Risk Findings Details</b></p>
  <img src="./assets/iam6.png" width="900" alt="Risk Findings Summary Dashboard">
  <br><br>
  <p><b>Telegram notify alert </b></p>
  <img src="./assets/iam4.png" width="900" alt="Risk Findings Summary Dashboard">
  <br><br>
  <p><b>other</b></p>
  <img src="./assets/iam5.png" width="450" alt="Risk Findings Summary Dashboard">
  <img src="./assets/iam7.png" width="450" alt="Risk Findings Summary Dashboard">
</div>



---

## 🚨 PROOF OF CONCEPT NOTICE

**THIS PROJECT HAS BEEN VALIDATED AGAINST A LIVE AWS ENVIRONMENT.**

### 👉 [PLEASE REFER TO AWS-README.MD](./AWS-README.md) 
**FOR FULL DOCUMENTATION OF THE MISCONFIGURATIONS DETECTED, CORRESPONDING AWS CONSOLE SCREENSHOTS, AND ATTACK-PATH CASE STUDIES.**

---


## 🏗️ Project Architecture

CloudLens is built using a **Modular Microservice Architecture**. This repository acts as the **Central Orchestrator**, linking specialized services via **Git Submodules**.

```text
CloudLens-IAM/ (Main Hub)
├── AWS-IAM-backend/      # Django-based Logic & Risk Engine (Submodule)
├── AWS-IAM-frontend/     # React-based Security Dashboard (Submodule)
├── docker-compose.yml    # Master Orchestration File
└── README.md             # You Are Here
```
## 🛠️ Tech Stack

- **Backend:** Python (Django REST Framework), Boto3 (AWS SDK).
- **Analysis Engine:** NetworkX (Graph Theory), Custom Policy Normalizer.
- **Frontend:** React 18, TypeScript, Tailwind CSS.
- **Visuals:** React-Force-Graph (D3-based physics), Recharts.
- **DevOps:** Docker, Docker Compose, Git Submodules.

---

## 🚀 Quick Start (Docker Orchestration)

To run the full suite with a single command, ensure you have **Docker Desktop** installed.

### 1. Clone the Project (Recursive)
Because this project uses microservices, you must clone with the `--recursive` flag to download the linked codebases:
```bash
git clone --recursive https://github.com/vishwas-adhikari/CloudLens-IAM.git
cd CloudLens-IAM

*Note: If you already cloned normally, run `git submodule update --init --recursive`.*

### 2. Configure Environment Variables
Navigate to the backend directory and create your environment file:
```bash
cd AWS-IAM-backend
# Create .env and add your details
# TELEGRAM_BOT_TOKEN=...
# TELEGRAM_CHAT_ID=...
# SECRET_KEY=any-random-string
cd ..
```

### 3. Launch CloudLens
Run the orchestrator from the root directory:
```bash
docker-compose up --build
```

### 4. Access the Platform
- **Dashboard UI:** [http://localhost:5173](http://localhost:5173)
- **API History:** [http://localhost:8000/api/history/](http://localhost:8000/api/history/)

---


## 🔎 Risk Engine Breakdown

CloudLens evaluates your environment against a specialized knowledge base of IAM risks and best practices:

| Severity | Risk Pattern | Security Impact |
| :--- | :--- | :--- |
| 🟥 **CRITICAL** | **Full Admin Access** | Identity has `AdministratorAccess` or `*:*` effective permissions. |
| 🟥 **CRITICAL** | **Public Trust** | Trust Policy allows `Principal: "*"` (Publicly assumable roles). |
| 🟥 **CRITICAL** | **Escalation Path** | Discovery of `sts:AssumeRole` chains leading to Administrative power. |
| 🟧 **HIGH** | **No-MFA Admin** | User has Administrator privileges but Multi-Factor Auth is disabled. |
| 🟧 **HIGH** | **Dangerous Write Actions** | Identity can grant permissions (`iam:CreatePolicy`, `iam:AttachUserPolicy`). |
| 🟧 **HIGH** | **Service Wildcards** | Excessive permissions like `s3:*` or `ec2:*` on all resources. |
| 🟨 **MEDIUM** | **PassRole Abuse** | `iam:PassRole` on `*` allows pivoting to compute services (EC2/Lambda). |
| 🟨 **MEDIUM** | **Weak Password Policy** | Account lacks modern complexity (length, symbols, rotation) requirements. |

---

## 🛡️ Security & Privacy Model

CloudLens is built on the principle of **Least Privilege**:
1. **Read-Only:** The tool requires only the AWS-managed `SecurityAudit` policy. It cannot modify or delete any resources.
2. **Local Processing:** All IAM JSON data is processed in your local Docker container. No data is sent to external servers.
3. **Encrypted at Rest:** Results are stored in a local SQLite database, keeping your security posture data private.

---

## ❓ Troubleshooting

**Submodule folders are empty?**  
Run `git submodule update --init --recursive`.

**Docker build fails?**  
Ensure Ports 5173 and 8000 are not being used by other applications.

**Backend unreachable?**  
Check the container logs: `docker logs cloudlens-backend`.

---
Developed by **[Vishwas]** | [LinkedIn](www.linkedin.com/in/vishwasadhikari) 
```





