This document is designed as your **Internal Technical Manual**. It covers the end-to-end setup for a live demonstration, assuming you are running it manually (without Docker) to show the inner workings of the code.

---

# 📘 CloudLens: Complete Demonstration Manual

This guide provides step-by-step instructions to set up the environment, configure the AWS "Lab," and perform a high-impact demonstration of the **CloudLens** platform.

---

##  Phase 1: Environment Preparation

Ensure your local machine has **Python 3.11+** and **Node.js 18+** installed.

### 1. Clone the Project
The project uses Git Submodules. You must initialize them to get the code for the engine and the UI.
```bash
git clone --recursive https://github.com/vishwas-adhikari/CloudLens-IAM.git
cd CloudLens-IAM
```

### 2. Backend Setup (The Engine)
```bash
cd AWS-IAM-backend
python -m venv venv

# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
python manage.py migrate
```

### **3. Frontend Setup (The Dashboard)**
Open a **new terminal** and follow these steps:
```bash
cd AWS-IAM-frontend

npm install
# 2. Manual verification: Ensure all specialized libraries are present
# Run this if you are setting up for the first time or if icons/graphs are missing:
npm install axios react-router-dom lucide-react recharts react-force-graph-2d

npm run dev
```

---


---

##  Phase 2: AWS Console Configuration (The "Lab")

For a successful demo, you need a "Scanner" identity and three specific "Traps" for the tool to find.

### 1. The Scanner (Safe Identity)
*   **Create User:** `CloudLens-Scanner`
*   **Permissions:** Attach **`SecurityAudit`** (Managed Policy).
*   **Security Credentials:** Create **Access Keys (CLI)**. Save these for the login screen.

### 2. The Traps (Vulnerabilities)
*   **Trap A (Critical - Admin):** Create a user `Dave-Admin` and attach `AdministratorAccess`. Do NOT enable MFA.
*   **Trap B (Critical - Public):** Create a role `Public-Storage-Access`. Edit the **Trust Relationship** and set `"Principal": {"AWS": "*"}`.
*   **Trap C (High - Wildcard):** Create a user `Wildcard-Willy`. Create an **Inline Policy** allowing `s3:*` on `Resource: "*"`.

---

##  Phase 3: Configuration & Integration

### 1. Telegram Bot Setup
1.  Message **@BotFather** on Telegram to create a bot and get the `API_TOKEN`.
2.  Message **@userinfobot** to get your `CHAT_ID`.
3.  Ensure you click **"Start"** on your new bot.

### 2. Backend .env File
Create `AWS-IAM-backend/.env`:
```ini
SECRET_KEY=demo_key_123
DEBUG=True
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_id_here
```

---

##  Phase 4: The Demonstration Flow

### Step 1: Launch the Servers
*   **Backend:** `python manage.py runserver` (Terminal 1)
*   **Frontend:** `npm run dev` (Terminal 2)

### Step 2: Connection & Ingestion
1.  Open `http://localhost:5173`.
2.  Enter the **Scanner Access Keys** from Phase 2.
3.  Click **Start Scan**. 
4.  *Narrative:* Explain that the tool is currently using Boto3 to pull live IAM JSON and passing it through the NetworkX graph engine.

### Step 3: The Dashboard (The "What")
1.  Show the **Risk Score**. Explain why it is high (Calculated from the 3 traps we set).
2.  Review the **Statistics Cards**. Point out that the tool discovered nearly 40 roles, including hidden AWS Service Roles.

### Step 4: Risk Findings (The "Why")
1.  Go to **Risk Findings**.
2.  Filter by **Critical**. Show the **Public Trust** finding.
3.  Expand **Dave-Admin**. Show that it caught both the "Admin Access" AND the "Missing MFA" simultaneously.

### Step 5: Graph Explorer (The "How")
1.  Switch to **Graph Explorer**.
2.  **Demonstrate Clustering:** Show how the red nodes pull together.
3.  **Find "The Internet":** Locate the node "The Internet" and follow the arrow to the `Public-Storage-Access` role.
4.  *Narrative:* "This visual representation allows an auditor to instantly see entry points that a text list might hide."

### Step 6: The Telegram Punchline
1.  Open your Telegram app.
2.  Show the **Formatted Report** that arrived automatically.
3.  *Narrative:* "Even if I'm away from my desk, CloudLens pushes the most critical findings directly to the security team's mobile devices."

---

##  Phase 5: Cleanup (Post-Demo)

To maintain security, always delete the traps after a demo:
1.  Delete `Dave-Admin`.
2.  Delete `Public-Storage-Access`.
3.  Delete `Wildcard-Willy`.
4.  Deactivate the `CloudLens-Scanner` access keys.

---
**Author:** Vishwas Adhikari
**Project:** CloudLens IAM Analyzer
**Date:** December 2025

