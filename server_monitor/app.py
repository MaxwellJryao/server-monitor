from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import time
from datetime import datetime
from nvitop import Device, GpuProcess, HostProcess
import sqlite3
import os
from functools import wraps
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# 创建主Flask应用
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 环境配置
app.config['ENV'] = os.environ.get('FLASK_ENV', 'development')  # 默认为开发环境
app.config['DEBUG'] = app.config['ENV'] == 'development'

# 邮件配置
if app.config['ENV'] == 'production':
    # 生产环境邮件配置
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 使用Gmail的SMTP服务器
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')
    app.config['USE_TEST_EMAIL'] = False
else:
    # 开发环境邮件配置 - 使用真实的邮件服务器
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 使用Gmail的SMTP服务器
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')
    app.config['USE_TEST_EMAIL'] = False  # 在开发环境中也使用真实邮件发送

# 初始化主数据库
db_users = SQLAlchemy(app)

# 初始化Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 自定义装饰器：确保用户是管理员
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'status': 'error', 'message': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated_function

# 自定义匿名用户类
class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.username = 'Guest'
        self.is_admin = False

login_manager.anonymous_user = Anonymous

# 用户模型
class User(UserMixin, db_users.Model):
    __tablename__ = 'user'
    id = db_users.Column(db_users.Integer, primary_key=True)
    username = db_users.Column(db_users.String(80), unique=True, nullable=False)
    email = db_users.Column(db_users.String(120), unique=True, nullable=False)
    password_hash = db_users.Column(db_users.String(120), nullable=False)
    is_admin = db_users.Column(db_users.Boolean, default=False)
    is_email_verified = db_users.Column(db_users.Boolean, default=False)
    email_verification_token = db_users.Column(db_users.String(100), unique=True)

    def __init__(self, username, email, password_hash, is_admin=False):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.email_verification_token = secrets.token_urlsafe(32)

    def get_id(self):
        return str(self.id)

# 发送验证邮件的函数
def send_verification_email(user):
    try:
        # 使用Python内置的smtplib库发送邮件
        msg = MIMEMultipart()
        msg['Subject'] = '验证您的账户 - 服务器监控系统'
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = user.email
        
        verification_url = url_for('verify_email', token=user.email_verification_token, _external=True)
        
        body = f"""
        <html>
        <body>
            <h2>欢迎使用服务器监控系统</h2>
            <p>您好 {user.username}，</p>
            <p>感谢您注册我们的服务。请点击下面的链接验证您的邮箱地址：</p>
            <p><a href="{verification_url}">{verification_url}</a></p>
            <p>如果您没有注册我们的服务，请忽略此邮件。</p>
            <p>此链接将在24小时后失效。</p>
            <p>祝好，<br>服务器监控系统团队</p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # 使用try-except块处理连接错误
        try:
            print(f"尝试连接到邮件服务器: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
            print(f"使用邮箱: {app.config['MAIL_USERNAME']}")
            
            with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
                server.starttls()
                server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                server.send_message(msg)
                
            print(f"验证邮件已成功发送至 {user.email}")
            return True
        except Exception as e:
            print(f"SMTP连接错误: {str(e)}")
            # 如果SMTP连接失败，尝试使用备用方法
            try:
                # 尝试使用SSL连接
                print("尝试使用SSL连接...")
                with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], 465) as server:
                    server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                    server.send_message(msg)
                print(f"使用SSL连接成功发送邮件至 {user.email}")
                return True
            except Exception as ssl_error:
                print(f"SSL连接也失败: {str(ssl_error)}")
                return False
            
    except Exception as e:
        print(f"发送验证邮件时出错: {str(e)}")
        return False

# 备用邮件发送函数 - 用于测试环境
def send_verification_email_test(user):
    """
    测试环境使用的邮件发送函数，不实际发送邮件，只打印信息
    """
    verification_url = url_for('verify_email', token=user.email_verification_token, _external=True)
    print(f"测试环境 - 验证邮件已发送至 {user.email}")
    print(f"验证链接: {verification_url}")
    return True

# 预约数据库
class ReservationDB:
    def __init__(self, app):
        self.app = app
        self.db = SQLAlchemy()
        
    def init_app(self):
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reservations.db'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.db.init_app(self.app)
        
    def create_all(self):
        with self.app.app_context():
            self.db.create_all()

# 预约模型
class Reservation(db_users.Model):
    __tablename__ = 'reservation'
    id = db_users.Column(db_users.Integer, primary_key=True)
    user_id = db_users.Column(db_users.Integer, nullable=False)
    gpu_uuid = db_users.Column(db_users.String(80), nullable=False)
    date = db_users.Column(db_users.Date, nullable=False)
    hour = db_users.Column(db_users.Integer, nullable=False)
    created_at = db_users.Column(db_users.DateTime, default=datetime.utcnow)

    __table_args__ = (db_users.UniqueConstraint('gpu_uuid', 'date', 'hour', name='unique_reservation'),)

# 初始化预约数据库
reservation_app = Flask('reservations')
db_reservations = ReservationDB(reservation_app)
db_reservations.init_app()

def init_databases():
    # 初始化用户数据库
    try:
        print("初始化用户数据库...")
        with app.app_context():
            db_users.create_all()
            
            # 检查是否需要创建默认用户
            admin = User.query.filter_by(username='admin').first()
            user1 = User.query.filter_by(username='user1').first()
            
            if not admin:
                print("创建管理员用户...")
                admin = User('admin', 'admin@example.com', generate_password_hash('admin123'), is_admin=True)
                admin.is_email_verified = True  # 默认管理员账户已验证
                db_users.session.add(admin)
                print("管理员用户 'admin' 创建成功，密码：admin123")
            elif not admin.is_admin:
                print("更新管理员权限...")
                admin.is_admin = True
                
            if not user1:
                print("创建普通用户...")
                user1 = User('user1', 'user1@example.com', generate_password_hash('user123'), is_admin=False)
                user1.is_email_verified = True  # 默认普通用户账户已验证
                db_users.session.add(user1)
                print("普通用户 'user1' 创建成功，密码：user123")
                
            try:
                db_users.session.commit()
                print("用户数据库初始化完成")
            except Exception as e:
                db_users.session.rollback()
                print(f"保存用户数据时出错: {str(e)}")
                raise
    except Exception as e:
        print(f"初始化用户数据库时出错: {str(e)}")
        raise

    # 初始化预约数据库
    try:
        print("初始化预约数据库...")
        db_reservations.create_all()
        print("预约数据库初始化完成")
    except Exception as e:
        print(f"初始化预约数据库时出错: {str(e)}")
        raise

# 初始化数据库
print("\n=== 开始初始化数据库 ===")
init_databases()
print("=== 数据库初始化完成 ===\n")

@login_manager.user_loader
def load_user(user_id):
    try:
        with app.app_context():
            user = User.query.get(int(user_id))
            if user:
                print(f"加载用户成功 - ID: {user.id}, 用户名: {user.username}, 管理员: {user.is_admin}")
            return user
    except Exception as e:
        print(f"加载用户时出错: {str(e)}")
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"尝试登录用户: {username}")
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.is_email_verified:
                flash('请先验证您的邮箱地址', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            print(f"用户 {username} 登录成功 (ID: {user.id}, 管理员: {user.is_admin})")
            return redirect(url_for('index'))
        else:
            if not user:
                print(f"用户 {username} 不存在")
            else:
                print(f"用户 {username} 密码错误")
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # 验证表单数据
        if not username or not email or not password or not confirm_password:
            flash('请填写所有必填字段', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('两次输入的密码不匹配', 'danger')
            return redirect(url_for('register'))
        
        # 检查用户名是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('用户名已被使用', 'danger')
            return redirect(url_for('register'))
        
        # 检查邮箱是否已存在
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('该邮箱已被注册', 'danger')
            return redirect(url_for('register'))
        
        # 创建新用户
        try:
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_admin=False
            )
            db_users.session.add(new_user)
            db_users.session.commit()
            
            # 发送验证邮件
            if send_verification_email(new_user):
                flash('注册成功！请检查您的邮箱以验证账户', 'success')
            else:
                # 如果邮件发送失败，提供验证链接
                verification_url = url_for('verify_email', token=new_user.email_verification_token, _external=True)
                flash(f'注册成功，但发送验证邮件失败。请使用以下链接验证您的账户: {verification_url}', 'warning')
            
            return redirect(url_for('login'))
        except Exception as e:
            db_users.session.rollback()
            print(f"注册用户时出错: {str(e)}")
            flash('注册过程中出错，请稍后再试', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        user = User.query.filter_by(email_verification_token=token).first()
        
        if not user:
            flash('无效的验证链接', 'danger')
            return render_template('email_verification.html')
        
        if user.is_email_verified:
            flash('您的邮箱已验证', 'info')
            return render_template('email_verification.html')
        
        user.is_email_verified = True
        user.email_verification_token = None  # 清除验证令牌
        db_users.session.commit()
        
        flash('邮箱验证成功！您现在可以登录了', 'success')
        return render_template('email_verification.html')
    except Exception as e:
        db_users.session.rollback()
        print(f"验证邮箱时出错: {str(e)}")
        flash('验证过程中出错，请稍后再试', 'danger')
        return render_template('email_verification.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/gpu-reservation')
@login_required
def gpu_reservation():
    return render_template('gpu_reservation.html')

@app.route('/api/reservations')
@login_required
def get_reservations():
    try:
        reservations = Reservation.query.all()
        result = {}
        print("\n=== 获取预约信息 ===")
        print(f"找到 {len(reservations)} 条预约记录")
        print(f"当前用户: {current_user.username} (ID: {current_user.id}, 管理员: {current_user.is_admin})")
        
        # 为每个预约添加用户信息
        for res in reservations:
            if res.gpu_uuid not in result:
                result[res.gpu_uuid] = []
            
            time_slot = f"{res.date.isoformat()}-{str(res.hour).zfill(2)}"
            # 添加用户信息到预约数据中
            with app.app_context():
                user = User.query.get(res.user_id)
                username = user.username if user else "未知用户"
            reservation_data = {
                'time_slot': time_slot,
                'user_id': res.user_id,
                'username': username
            }
            result[res.gpu_uuid].append(reservation_data)
            print(f"GPU: {res.gpu_uuid}, 时间槽: {time_slot}, 用户: {username}")
        
        print("返回数据:", result)
        print("===================\n")
        return jsonify(result)
    except Exception as e:
        print(f"获取预约信息时出错: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/reservations', methods=['POST'])
@login_required
def add_reservation():
    try:
        data = request.json
        if not data:
            return jsonify({'status': 'error', 'message': '无效的请求数据'}), 400
            
        reservations = data.get('reservations', [])
        if not reservations:
            return jsonify({'status': 'error', 'message': '缺少预约数据'}), 400
            
        print(f"\n=== 收到预约请求 ===")
        print(f"用户: {current_user.username} (ID={current_user.id}, 管理员={current_user.is_admin})")
        print(f"预约数据: {reservations}")
        
        success_count = 0
        error_messages = []
        
        for reservation in reservations:
            gpu_uuid = reservation.get('gpu_uuid')
            time_slots = reservation.get('time_slots', [])
            
            if not gpu_uuid:
                error_messages.append('缺少GPU UUID')
                continue
            if not time_slots:
                continue
                
            print(f"\n处理GPU {gpu_uuid} 的预约:")
            for time_slot in time_slots:
                try:
                    # 期望的格式: YYYY-MM-DD-HH
                    if not time_slot or len(time_slot.split('-')) != 4:
                        error_messages.append(f'无效的时间格式: {time_slot}，应为YYYY-MM-DD-HH')
                        continue
                    
                    year, month, day, hour = time_slot.split('-')
                    date_str = f"{year}-{month}-{day}"
                    
                    try:
                        date = datetime.strptime(date_str, '%Y-%m-%d').date()
                        hour = int(hour)
                        if hour < 0 or hour > 23:
                            error_messages.append(f'无效的小时数: {hour}')
                            continue
                    except ValueError as e:
                        error_messages.append(f'无效的日期或时间: {date_str}-{hour}')
                        continue
                    
                    # 检查是否已存在预约
                    existing = Reservation.query.filter_by(
                        gpu_uuid=gpu_uuid,
                        date=date,
                        hour=hour
                    ).first()
                    
                    if existing:
                        print(f"时间段已被预约: {time_slot}")
                        error_messages.append(f'时间段 {time_slot} 已被预约')
                        continue
                    
                    # 创建新预约
                    new_reservation = Reservation(
                        user_id=current_user.id,
                        gpu_uuid=gpu_uuid,
                        date=date,
                        hour=hour
                    )
                    db_users.session.add(new_reservation)
                    
                    try:
                        db_users.session.commit()
                        success_count += 1
                        print(f"成功添加预约: {time_slot}")
                    except Exception as e:
                        db_users.session.rollback()
                        error_msg = f'保存预约时出错 ({time_slot}): {str(e)}'
                        print(error_msg)
                        error_messages.append(error_msg)
                        
                except Exception as e:
                    error_msg = f'处理时间槽出错 ({time_slot}): {str(e)}'
                    print(error_msg)
                    error_messages.append(error_msg)
        
        print("\n=== 预约处理结果 ===")
        print(f"成功预约数: {success_count}")
        if error_messages:
            print(f"错误信息: {error_messages}")
        
        if success_count > 0:
            return jsonify({
                'status': 'success',
                'message': f'成功添加 {success_count} 个预约' + (f'，但有 {len(error_messages)} 个错误' if error_messages else ''),
                'errors': error_messages
            })
        else:
            return jsonify({
                'status': 'error',
                'message': '预约失败',
                'errors': error_messages
            }), 400
            
    except Exception as e:
        print(f"预约处理时出错: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'预约处理时出错: {str(e)}'
        }), 500

@app.route('/api/reservations', methods=['DELETE'])
@login_required
def cancel_reservation():
    try:
        data = request.json
        if not data:
            return jsonify({'status': 'error', 'message': '无效的请求数据'}), 400
            
        cancellations = data.get('cancellations', [])
        if not cancellations:
            return jsonify({'status': 'error', 'message': '缺少取消预约数据'}), 400
            
        print(f"\n=== 收到取消预约请求 ===")
        print(f"当前用户: {current_user.username} (ID={current_user.id})")
        
        # 检查用户权限
        print(f"当前用户权限检查 - 用户名: {current_user.username}, ID: {current_user.id}, 管理员: {current_user.is_admin}")
        
        success_count = 0
        error_messages = []
        
        for cancellation in cancellations:
            gpu_uuid = cancellation.get('gpu_uuid')
            time_slots = cancellation.get('time_slots', [])
            
            if not gpu_uuid:
                error_messages.append('缺少GPU UUID')
                continue
            if not time_slots:
                continue
                
            print(f"\n处理GPU {gpu_uuid} 的取消请求:")
            for time_slot in time_slots:
                try:
                    # 期望的格式: YYYY-MM-DD-HH
                    if not time_slot or len(time_slot.split('-')) != 4:
                        error_messages.append(f'无效的时间格式: {time_slot}，应为YYYY-MM-DD-HH')
                        continue
                    
                    year, month, day, hour = time_slot.split('-')
                    date_str = f"{year}-{month}-{day}"
                    
                    try:
                        date = datetime.strptime(date_str, '%Y-%m-%d').date()
                        hour = int(hour)
                        if hour < 0 or hour > 23:
                            error_messages.append(f'无效的小时数: {hour}')
                            continue
                    except ValueError as e:
                        error_messages.append(f'无效的日期或时间: {date_str}-{hour}')
                        continue
                    
                    # 查找预约记录
                    reservation = Reservation.query.filter_by(
                        gpu_uuid=gpu_uuid,
                        date=date,
                        hour=hour
                    ).first()
                    
                    if not reservation:
                        print(f"未找到预约记录: {time_slot}")
                        error_messages.append(f'未找到预约记录: {time_slot}')
                        continue
                    
                    # 获取被取消预约的用户信息（用于日志）
                    reservation_user = User.query.get(reservation.user_id)
                    reservation_username = reservation_user.username if reservation_user else "未知用户"
                    print(f"预约信息 - 预约用户: {reservation_username} (ID: {reservation.user_id})")
                    print(f"权限检查 - 当前用户是管理员: {current_user.is_admin}, 是预约本人: {reservation.user_id == current_user.id}")
                    
                    # 检查权限：只有管理员或预约本人可以取消预约
                    if not current_user.is_admin and reservation.user_id != current_user.id:
                        error_msg = f'无权取消其他用户的预约: {time_slot} (预约用户: {reservation_username})'
                        print(error_msg)
                        error_messages.append(error_msg)
                        continue
                    
                    # 删除预约
                    db_users.session.delete(reservation)
                    
                    try:
                        db_users.session.commit()
                        success_count += 1
                        print(f"成功取消预约: {time_slot} (预约用户: {reservation_username})")
                    except Exception as e:
                        db_users.session.rollback()
                        error_msg = f'保存取消操作时出错 ({time_slot}): {str(e)}'
                        print(error_msg)
                        error_messages.append(error_msg)
                        
                except Exception as e:
                    error_msg = f'处理时间槽出错 ({time_slot}): {str(e)}'
                    print(error_msg)
                    error_messages.append(error_msg)
        
        print("\n=== 取消预约处理结果 ===")
        print(f"成功取消数: {success_count}")
        if error_messages:
            print(f"错误信息: {error_messages}")
        
        if success_count > 0:
            return jsonify({
                'status': 'success',
                'message': f'成功取消 {success_count} 个预约' + (f'，但有 {len(error_messages)} 个错误' if error_messages else ''),
                'errors': error_messages
            })
        else:
            return jsonify({
                'status': 'error',
                'message': '取消预约失败',
                'errors': error_messages
            }), 400
            
    except Exception as e:
        print(f"取消预约时出错: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'取消预约时出错: {str(e)}'
        }), 500

def get_system_info(verbose=False):
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    # 获取所有磁盘分区信息
    all_disks = ['/tmp', '/scratch', '/shared/storage-01']
    disks = []
    monitored_disks = []
    for partition in psutil.disk_partitions(all=True):
        try:
            if partition.mountpoint not in all_disks or partition.mountpoint in monitored_disks:
                continue
            monitored_disks.append(partition.mountpoint)
            disk_usage = psutil.disk_usage(partition.mountpoint)
            disks.append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total': int(disk_usage.total),
                'used': int(disk_usage.used),
                'free': int(disk_usage.free),
                'percent': float(disk_usage.percent)
            })
            if verbose:
                print(f"磁盘 {partition.device} 挂载于 {partition.mountpoint}: 使用率 {disk_usage.percent}%")
        except Exception as e:
            if verbose:
                print(f"获取磁盘 {partition.device} 信息时出错: {str(e)}")
            continue

    
    gpus = []
    try:
        # 直接获取所有GPU设备
        all_devices = Device.all()
        if verbose:
            print(f"检测到 {len(all_devices)} 个GPU设备")
        
        for device in all_devices:
            if verbose:
                print(f"正在处理 GPU {device.index}")
            
            # 获取GPU进程信息
            processes = []
            try:
                device_processes = device.processes()
                for pid, process in device_processes.items():
                    try:
                        host_process = process.host
                        cmd = host_process.cmdline()
                        cmd_str = cmd[0] if cmd else ''
                        processes.append({
                            'pid': int(pid),
                            'username': str(host_process.username()),
                            'gpu_memory': int(process.gpu_memory() or 0),
                            'command': str(cmd_str)
                        })
                    except Exception as e:
                        print(f"处理进程信息时出错: {e}")
                        continue
            except Exception as e:
                print(f"获取GPU进程时出错: {e}")

            try:
                # 获取GPU基本信息，确保所有值都是基本类型
                gpu_info = {
                    'id': int(device.index),
                    'uuid': str(device.uuid()),  # 添加UUID
                    'name': str(device.name()),
                    'load': float(device.gpu_utilization() or 0),
                    'memoryTotal': int(device.memory_total() or 0),
                    'memoryUsed': int(device.memory_used() or 0),
                    'memoryFree': int(device.memory_free() or 0),
                    'temperature': int(device.temperature() or 0),
                    'power_usage': float(device.power_usage() / 1000.0 if device.power_usage() is not None else 0),
                    'power_limit': float(device.power_limit() / 1000.0 if device.power_limit() is not None else 0),
                    'fan_speed': int(device.fan_speed() or 0),
                    'processes': processes
                }
                gpus.append(gpu_info)
                if verbose:
                    print(f"GPU {device.index} 信息已添加")
            except Exception as e:
                print(f"处理GPU信息时出错: {e}")
                continue
            
    except Exception as e:
        print(f"获取GPU信息时出错: {str(e)}")
        import traceback
        traceback.print_exc()
    
    result = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'cpu': {
            'percent': float(cpu_percent),
            'count': int(psutil.cpu_count()),
            'freq': float(psutil.cpu_freq().current if psutil.cpu_freq() else 0)
        },
        'memory': {
            'total': int(memory.total),
            'available': int(memory.available),
            'percent': float(memory.percent),
            'used': int(memory.used)
        },
        'disks': disks,
        'gpus': gpus
    }
    
    if verbose:
        print(f"返回数据中包含 {len(gpus)} 个GPU信息")
        print(f"返回数据中包含 {len(disks)} 个磁盘信息")
    return result

@app.route('/api/system-info')
def system_info(verbose=False):
    info = get_system_info(verbose)
    response = jsonify(info)
    if verbose:
        print(f"API返回数据中包含 {len(info['gpus'])} 个GPU信息")
    return response

@app.route('/user_management')
@login_required
def user_management():
    if not current_user.is_admin:
        flash('您没有权限访问此页面', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/user/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': '您没有权限执行此操作'})
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    # 检查用户名是否已存在
    if data.get('username') != user.username:
        existing_user = User.query.filter_by(username=data.get('username')).first()
        if existing_user:
            return jsonify({'success': False, 'message': '用户名已存在'})
    
    # 检查邮箱是否已存在
    if data.get('email') != user.email:
        existing_email = User.query.filter_by(email=data.get('email')).first()
        if existing_email:
            return jsonify({'success': False, 'message': '邮箱已被注册'})
    
    # 更新用户信息
    user.username = data.get('username')
    user.email = data.get('email')
    user.is_admin = data.get('is_admin', False)
    user.is_email_verified = data.get('email_verified', False)
    
    # 如果提供了新密码，则更新密码
    if data.get('password'):
        user.password_hash = generate_password_hash(data.get('password'))
    
    db_users.session.commit()
    return jsonify({'success': True, 'message': '用户信息已更新'})

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': '您没有权限执行此操作'})
    
    user = User.query.get_or_404(user_id)
    
    # 不允许删除自己
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': '不能删除当前登录的用户'})
    
    db_users.session.delete(user)
    db_users.session.commit()
    return jsonify({'success': True, 'message': '用户已删除'})

@app.route('/user/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': '您没有权限执行此操作'})
    
    data = request.get_json()
    
    # 验证必填字段
    if not all([data.get('username'), data.get('email'), data.get('password')]):
        return jsonify({'success': False, 'message': '请填写所有必填字段'})
    
    # 检查用户名是否已存在
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'success': False, 'message': '用户名已存在'})
    
    # 检查邮箱是否已存在
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'success': False, 'message': '邮箱已被注册'})
    
    # 创建新用户
    new_user = User(
        username=data.get('username'),
        email=data.get('email'),
        password_hash=generate_password_hash(data.get('password')),
        is_admin=data.get('is_admin', False),
        is_email_verified=data.get('email_verified', False)
    )
    
    db_users.session.add(new_user)
    db_users.session.commit()
    
    return jsonify({'success': True, 'message': '用户已创建'})

@app.route('/api/gpus')
@login_required
def get_gpus():
    try:
        devices = Device.all()
        gpus = []
        for device in devices:
            gpu_info = {
                'id': device.index,
                'uuid': device.uuid(),
                'name': device.name()
            }
            gpus.append(gpu_info)
        return jsonify(gpus)
    except Exception as e:
        print(f"获取GPU列表时出错: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # 检查邮件配置
    print("\n=== 邮件服务器配置 ===")
    print(f"环境: {app.config['ENV']}")
    print(f"邮件服务器: {app.config['MAIL_SERVER']}")
    print(f"邮件端口: {app.config['MAIL_PORT']}")
    print(f"发件人邮箱: {app.config['MAIL_DEFAULT_SENDER']}")
    
    # 检查环境变量
    if not os.environ.get('MAIL_USERNAME') or not os.environ.get('MAIL_PASSWORD'):
        print("警告: 未设置邮件服务器环境变量 MAIL_USERNAME 或 MAIL_PASSWORD")
        print("请设置以下环境变量以启用邮件发送功能:")
        print("export MAIL_USERNAME=your-email@gmail.com")
        print("export MAIL_PASSWORD=your-app-password")
        print("export MAIL_DEFAULT_SENDER=your-email@gmail.com")
        print("或者直接在代码中设置这些值")
    else:
        print("邮件服务器环境变量已设置")
    
    print("=========================\n")
    
    # 启动时检查GPU
    print("\n=== 系统启动时的GPU检查 ===")
    devices = Device.all()
    print(f"系统中共检测到 {len(devices)} 个GPU设备：")
    for device in devices:
        print(f"GPU {device.index}: {device.name}")
    print("=========================\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True) 