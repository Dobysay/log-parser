import re, os, sys, glob, json, argparse, configparser
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, request, session, send_from_directory
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, DateTime, BigInteger, Index, func
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import bcrypt

# --- КОНФИГУРАЦИЯ ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.ini')
config = configparser.ConfigParser()
config.read(CONFIG_PATH)

db_type = config['DATABASE']['db_type']
if db_type == 'sqlite':
    DB_URL = f"sqlite:///{config['DATABASE']['name']}"
else:
    DB_URL = f"{db_type}://{config['DATABASE']['user']}:{config['DATABASE']['password']}@{config['DATABASE']['host']}:{config['DATABASE']['port']}/{config['DATABASE']['name']}"

# --- МОДЕЛИ БД ---
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

class LogEntry(Base):
    __tablename__ = 'log_entries'
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    request = Column(String(500))
    status = Column(Integer)
    size = Column(BigInteger)
    user_agent = Column(String(500))
    __table_args__ = (Index('ix_ip_ts', 'ip', 'timestamp'),)

    def to_dict(self):
        return {'id': self.id, 'ip': self.ip, 'timestamp': self.timestamp.isoformat(),
                'request': self.request, 'status': self.status, 'size': self.size, 'user_agent': self.user_agent}

# --- БД ---
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if db_type == 'sqlite' else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def init_db():
    Base.metadata.create_all(engine)
    session = SessionLocal()
    if not session.query(User).filter_by(username='admin').first():
        hash_pw = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
        session.add(User(username='admin', password_hash=hash_pw))
        session.commit()
    session.close()
    print("✅ БД инициализирована")

# --- ПАРСЕР ---
LOG_PATTERN = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"[^"]*"\s+"(?P<ua>[^"]*)"')
TIME_FMT = '%d/%b/%Y:%H:%M:%S %z'

def parse_files(force=False):
    log_dir = config['LOGS']['log_dir']
    mask = config['LOGS']['file_mask']
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        with open(os.path.join(log_dir, 'access.log'), 'w') as f:
            f.write('192.168.1.1 - - [10/Jun/2026:12:00:01 +0300] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n')
            f.write('10.0.0.5 - - [10/Jun/2026:12:05:42 +0300] "GET /api/data HTTP/1.1" 404 512 "-" "Chrome/120"\n')
    
    files = sorted(glob.glob(os.path.join(log_dir, mask)))
    if not files:
        return {'status': 'warning', 'message': 'Файлы не найдены', 'parsed': 0}

    stats = {'total_parsed': 0, 'errors': []}
    session = SessionLocal()
    try:
        for fpath in files:
            try:
                batch = []
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        m = LOG_PATTERN.match(line.strip())
                        if m:
                            d = m.groupdictPW() # Note: simplified for online
                            # Простой парсинг для демо
                            stats['total_parsed'] += 1
                            batch.append(LogEntry(
                                ip=d['ip'], 
                                timestamp=datetime.strptime(d['time'], TIME_FMT),
                                request=d['request'], 
                                status=int(d['status']), 
                                size=0 if d['size']=='-' else int(d['size']),
                                user_agent=d['ua']
                            ))
                if batch:
                    session.bulk_save_objects(batch)
                    session.commit()
            except Exception as e:
                stats['errors'].append(str(e))
        return {'status': 'ok', 'parsed': stats['total_parsed']}
    finally:
        session.close()

# --- FLASK API ---
app = Flask(__name__, static_folder='client')
app.secret_key = config['API']['secret_key']
CORS(app, supports_credentials=True)

# Раздача фронтенда
@app.route('/')
def index():
    return send_from_directory('client', 'index.html')

@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory('client', path)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    session_db = SessionLocal()
    user = session_db.query(User).filter_by(username=data.get('username')).first()
    session_db.close()
    if user and bcrypt.checkpw(data.get('password', '').encode(), user.password_hash.encode()):
        session['user_id'] = user.id
        return jsonify({'status': 'ok', 'username': user.username})
    return jsonify({'status': 'error', 'message': 'Неверный логин или пароль'}), 401

@app.route('/api/parse', methods=['POST'])
@login_required
def force_parse():
    return jsonify(parse_files(force=True))

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    ip = request.args.get('ip')
    group_by = request.args.get('group_by')
    session_db = SessionLocal()
    try:
        q = session_db.query(LogEntry)
        if ip: q = q.filter(LogEntry.ip == ip)
        
        if group_by == 'ip':
            rows = q.with_entities(LogEntry.ip, func.count(LogEntry.id)).group_by(LogEntry.ip).all()
            data = [{'ip': r[0], 'count': r[1]} for r in rows]
        else:
            data = [e.to_dict() for e in q.limit(100).all()]
        return jsonify({'status': 'ok', 'count': len(data), 'data': data})
    finally:
        session_db.close()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
