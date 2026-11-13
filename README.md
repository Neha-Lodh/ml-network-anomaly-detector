# 🛡️ ML-Based Network Anomaly Detector

A beginner-friendly, **final-year cybersecurity project** that uses Machine
Learning to analyze network traffic logs, detect suspicious/anomalous
activity, and present the results in a clean, dark-themed Flask web
dashboard.

> ⚠️ **Scope & ethics:** This is a *defensive, educational* project. It only
> analyzes traffic **data you already have** (CSV logs). It does **not**
> scan networks, exploit systems, capture live traffic, or contain any
> attack/malware code. The sample dataset is 100% synthetic.

---

## 1. What this project does

1. You upload a CSV file of network traffic records.
2. The app **validates and cleans** the data (removes duplicates, fixes
   missing/invalid values).
3. It extracts features (ports, protocol, duration, packet count, bytes
   transferred, failed connections).
4. Two ML models analyze each record:
   - **Isolation Forest** (unsupervised) — flags statistical outliers.
   - **Random Forest Classifier** (supervised) — predicts anomaly probability.
5. Both outputs are combined into a **0–100 risk score**, mapped to
   **Low / Medium / High**, with a plain-English explanation.
6. Results are stored in **MySQL** and shown on the **Dashboard**,
   **Traffic Analysis**, and **Alerts** pages with Chart.js visualizations.

---

## 2. Tech stack

| Layer          | Technology |
|----------------|------------|
| Backend        | Python, Flask |
| ML             | scikit-learn (Isolation Forest, Random Forest), pandas, NumPy, joblib |
| Frontend       | HTML, CSS, JavaScript, Chart.js |
| Database       | MySQL (parameterized queries via `mysql-connector-python`) |
| Config/secrets | `python-dotenv` + `.env` |

---

## 3. Project structure

```
ml_network_anomaly_detector/
│
├── app.py                     # Flask application (routes)
├── config.py                  # Loads settings from .env
├── database.py                # All MySQL queries (parameterized)
├── auth.py                    # Login, roles, CSRF, password hashing, lockout
├── preprocessing.py           # Data cleaning + feature extraction
├── ml_predict.py              # Loads models, runs predictions
├── risk_scoring.py            # 0-100 risk score + Low/Medium/High + explanation
├── train_model.py             # Trains & saves Isolation Forest + Random Forest
│
├── schema.sql                 # MySQL database schema
├── requirements.txt           # Python dependencies
├── .env.example                # Template for environment variables
├── .gitignore
│
├── data/
│   ├── generate_sample_data.py   # Creates synthetic sample CSV
│   └── sample_network_traffic.csv
│
├── models/                    # Saved .pkl files (created by train_model.py)
│   ├── isolation_forest.pkl
│   ├── random_forest.pkl
│   └── scaler.pkl
│
├── templates/                 # Jinja2 HTML templates
│   ├── base.html
│   ├── home.html
│   ├── dashboard.html
│   ├── traffic_analysis.html
│   ├── alerts.html
│   ├── ml_model.html
│   ├── login.html / setup.html / register.html / account.html
│   ├── admin_users.html       # User management (admin only)
│   └── error.html
│
├── static/
│   ├── css/style.css          # Dark cybersecurity theme
│   └── js/dashboard.js        # Chart.js rendering
│
├── tests/test_auth.py         # Authentication test-suite
└── uploads/                   # Temporary storage for uploaded CSVs
```

---

## 4. Prerequisites

- Python 3.10+ installed
- MySQL Server 8.x installed and running (MariaDB also works)
- `pip` and `git` installed

---

## 5. Installation (step-by-step)

Open **Command Prompt / Terminal** in the project folder.

### Step 1 — Create and activate a virtual environment

```cmd
python -m venv venv
venv\Scripts\activate          (Windows)
source venv/bin/activate       (macOS/Linux)
```

### Step 2 — Install dependencies

```cmd
pip install -r requirements.txt
```

### Step 3 — Set up the database

Log into MySQL and run the schema file:

```cmd
mysql -u root -p < schema.sql
```

This creates a database called `network_anomaly_db` with two tables:
`traffic_records` and `alerts`.

### Step 4 — Configure environment variables

Copy the example file and fill in your real MySQL password:

```cmd
copy .env.example .env        (Windows)
cp .env.example .env          (macOS/Linux)
```

Edit `.env`:

```
SECRET_KEY=some-random-string
FLASK_DEBUG=True
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_actual_mysql_password
DB_NAME=network_anomaly_db
MAX_UPLOAD_SIZE_MB=10
```

**Never commit your real `.env` file** — it's already listed in `.gitignore`.

### Step 5 — (Optional) Regenerate the sample dataset

A sample CSV is already included at `data/sample_network_traffic.csv`.
To generate a fresh/different one:

```cmd
python data/generate_sample_data.py
```

### Step 6 — Train the ML models

```cmd
python train_model.py
```

You should see output ending in `Done. Models saved in the models/ folder.`
Trained model files (`isolation_forest.pkl`, `random_forest.pkl`,
`scaler.pkl`) are already included in this project, but you can retrain
any time — including directly from the **ML Model** page in the app.

### Step 7 — Run the Flask app

```cmd
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

### Step 8 — Test it

0. On first run you'll be sent to **/setup** to create the administrator account, then log in.
1. Go to **Traffic Analysis** → upload `data/sample_network_traffic.csv`.
2. You'll see a results table with risk scores and explanations.
3. Go to **Dashboard** to see charts update.
4. Go to **Alerts** to see/filter detected anomalies and mark them Reviewed/Resolved.

---

## 6. Database setup details

`schema.sql` creates:

- **`traffic_records`** — every analyzed row (raw fields + prediction results)
- **`alerts`** — one row per detected anomaly, linked to `traffic_records`
  via a foreign key, with a `status` column (`New` / `Reviewed` / `Resolved`)

All queries in `database.py` use **parameterized placeholders (`%s`)** —
never string formatting — to prevent SQL injection.

To reset the database at any time:

```sql
DROP DATABASE network_anomaly_db;
SOURCE schema.sql;
```

---

## 6b. Authentication & roles

The whole app (except the Home page and `/login`) now requires a login.

**First run:** open the app → you are redirected to `/setup` → create the
administrator. After that, `/setup` is permanently closed.

| Role | Can do |
|------|--------|
| `admin` | Everything: dashboard, upload/analyse, alerts, **retrain models**, **manage users** (`/admin/users`) |
| `analyst` | Dashboard, upload/analyse CSVs, view and update alerts |

**Security features**

- Passwords stored only as salted hashes (Werkzeug scrypt) — never plain text
- Password policy: min length (default 8), must include a letter and a number
- Account lockout after 5 failed logins for 15 minutes (configurable)
- Generic "Invalid username or password" message (no user enumeration)
- New session on every login (prevents session fixation); sessions expire after 60 minutes
- Cookies are `HttpOnly` + `SameSite=Lax` (set `SESSION_COOKIE_SECURE=True` behind HTTPS)
- CSRF token required on every POST request
- Open-redirect-safe `?next=` handling
- Disabling or deleting a user ends their session immediately
- The last active admin cannot be demoted, disabled or deleted
- `/api/*` returns JSON `401`/`403` instead of redirecting

**Settings** (all optional, in `.env`): `ALLOW_REGISTRATION`, `MIN_PASSWORD_LENGTH`,
`MAX_FAILED_LOGINS`, `LOCKOUT_MINUTES`, `SESSION_LIFETIME_MINUTES`, `SESSION_COOKIE_SECURE`.

**Run the tests** (uses a temporary SQLite DB, no MySQL needed):

```cmd
python -m unittest tests.test_auth -v
```

> If you already created the MySQL database earlier, you don't need to do
> anything — the `users` table is created automatically on first start.
> Before deploying anywhere public, set a strong `SECRET_KEY` and
> `FLASK_DEBUG=False` (the app refuses to start with the default key when debug is off).

---

## 7. How the risk score works (for your viva)

```
risk_score = round( (0.6 × Isolation_Forest_anomaly_likelihood
                    + 0.4 × Random_Forest_anomaly_probability) × 100 )

risk_level:
    0–39   -> Low
    40–69  -> Medium
    70–100 -> High
```

The explanation text is generated by simple rule checks (high failed
connections, high packet count, large byte volume, very short duration,
uncommon destination port) — this is separate from the ML model itself,
just to make the output human-readable.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `Access denied for user` | Check `DB_USER` / `DB_PASSWORD` in `.env`. The app now auto-falls back to a local SQLite database (`data/anomaly.db`), so it still runs. Set `DB_BACKEND=sqlite` to skip MySQL entirely, or `DB_BACKEND=mysql` to require it. |
| `Unknown database 'network_anomaly_db'` | Run `mysql -u root -p < schema.sql` |
| `ML models not found` | Run `python train_model.py` |
| Dashboard shows "Could not load dashboard data" | MySQL isn't running, or `.env` is misconfigured |
| CSV upload fails validation | Make sure your CSV has all required columns (see Traffic Analysis page) |

---

## 9. Git / GitHub upload commands

```cmd
git init
git add .
git commit -m "Initial commit: ML-Based Network Anomaly Detector"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```

Double-check `.env` is **not** tracked before pushing:

```cmd
git status
```

(If `.env` appears, run `git rm --cached .env` before committing.)

---

## 10. Possible future improvements (mention in viva if asked)

- Real-time traffic capture (e.g. via `scapy`) instead of CSV upload
- Email/SMS notifications for High-risk alerts
- More advanced models (XGBoost, LSTM for sequential traffic)
- Model evaluation metrics page (precision/recall/F1, confusion matrix)

---

## 11. License / Disclaimer

Educational project. Provided as-is for academic purposes. Do not use
against networks or systems you do not own or have explicit permission
to monitor.
