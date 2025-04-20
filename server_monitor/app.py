from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import time
from datetime import datetime
from nvitop import Device, GpuProcess, HostProcess

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 请更改为随机字符串
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///server_monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
db = SQLAlchemy(app)

# 初始化Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    reservations = db.relationship('Reservation', backref='user', lazy=True)

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

# 预约模型
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gpu_uuid = db.Column(db.String(80), nullable=False)
    date = db.Column(db.Date, nullable=False)
    hour = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('gpu_uuid', 'date', 'hour', name='unique_reservation'),)

# 创建数据库表
with app.app_context():
    db.create_all()
    # 添加默认用户（如果不存在）
    if not User.query.filter_by(username='admin').first():
        admin = User('admin', generate_password_hash('admin123'))
        db.session.add(admin)
    if not User.query.filter_by(username='user1').first():
        user1 = User('user1', generate_password_hash('user123'))
        db.session.add(user1)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误')
    
    return render_template('login.html')

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

# 获取预约信息
@app.route('/api/reservations')
@login_required
def get_reservations():
    try:
        reservations = Reservation.query.all()
        result = {}
        print("\n=== 获取预约信息 ===")
        print(f"找到 {len(reservations)} 条预约记录")
        
        # 为每个预约添加用户信息
        for res in reservations:
            if res.gpu_uuid not in result:
                result[res.gpu_uuid] = []
            
            time_slot = f"{res.date.isoformat()}-{str(res.hour).zfill(2)}"
            # 添加用户信息到预约数据中
            reservation_data = {
                'time_slot': time_slot,
                'user_id': res.user_id,
                'username': User.query.get(res.user_id).username
            }
            result[res.gpu_uuid].append(reservation_data)
            print(f"GPU: {res.gpu_uuid}, 时间槽: {time_slot}, 用户: {reservation_data['username']}")
        
        print("返回数据:", result)
        print("===================\n")
        return jsonify(result)
    except Exception as e:
        print(f"获取预约信息时出错: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# 添加预约
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
            
        print(f"收到预约请求: {reservations}")
        
        for reservation in reservations:
            gpu_uuid = reservation.get('gpu_uuid')
            time_slots = reservation.get('time_slots', [])
            
            if not gpu_uuid:
                return jsonify({'status': 'error', 'message': '缺少GPU UUID'}), 400
            if not time_slots:
                continue
                
            for time_slot in time_slots:
                try:
                    # 期望的格式: YYYY-MM-DD-HH
                    if not time_slot or len(time_slot.split('-')) != 4:
                        return jsonify({'status': 'error', 'message': f'无效的时间格式: {time_slot}，应为YYYY-MM-DD-HH'}), 400
                    
                    year, month, day, hour = time_slot.split('-')
                    date_str = f"{year}-{month}-{day}"
                    
                    try:
                        date = datetime.strptime(date_str, '%Y-%m-%d').date()
                        hour = int(hour)
                        if hour < 0 or hour > 23:
                            return jsonify({'status': 'error', 'message': f'无效的小时数: {hour}'}), 400
                    except ValueError as e:
                        return jsonify({'status': 'error', 'message': f'无效的日期或时间: {date_str}-{hour}'}), 400
                    
                    # 检查是否已存在预约
                    existing = Reservation.query.filter_by(
                        gpu_uuid=gpu_uuid,
                        date=date,
                        hour=hour
                    ).first()
                    
                    if existing:
                        print(f"时间段已存在预约: {time_slot}")
                        continue
                    
                    reservation = Reservation(
                        user_id=current_user.id,
                        gpu_uuid=gpu_uuid,
                        date=date,
                        hour=hour
                    )
                    db.session.add(reservation)
                    print(f"添加预约: {time_slot}")
                    
                except Exception as e:
                    print(f"处理时间槽时出错: {time_slot}, 错误: {str(e)}")
                    return jsonify({'status': 'error', 'message': f'处理时间槽时出错: {str(e)}'}), 400
        
        try:
            db.session.commit()
            print("预约保存成功")
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            print(f"保存预约时出错: {str(e)}")
            return jsonify({'status': 'error', 'message': f'保存预约时出错: {str(e)}'}), 400
            
    except Exception as e:
        print(f"预约处理时出错: {str(e)}")
        return jsonify({'status': 'error', 'message': f'预约处理时出错: {str(e)}'}), 500

# 取消预约
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
            
        print(f"收到取消预约请求: {cancellations}, 用户ID={current_user.id}")
        
        for cancellation in cancellations:
            gpu_uuid = cancellation.get('gpu_uuid')
            time_slots = cancellation.get('time_slots', [])
            
            if not gpu_uuid:
                return jsonify({'status': 'error', 'message': '缺少GPU UUID'}), 400
            if not time_slots:
                continue
                
            for time_slot in time_slots:
                try:
                    # 期望的格式: YYYY-MM-DD-HH
                    if not time_slot or len(time_slot.split('-')) != 4:
                        return jsonify({'status': 'error', 'message': f'无效的时间格式: {time_slot}，应为YYYY-MM-DD-HH'}), 400
                    
                    year, month, day, hour = time_slot.split('-')
                    date_str = f"{year}-{month}-{day}"
                    
                    try:
                        date = datetime.strptime(date_str, '%Y-%m-%d').date()
                        hour = int(hour)
                        if hour < 0 or hour > 23:
                            return jsonify({'status': 'error', 'message': f'无效的小时数: {hour}'}), 400
                    except ValueError as e:
                        return jsonify({'status': 'error', 'message': f'无效的日期或时间: {date_str}-{hour}'}), 400
                    
                    print(f"尝试取消预约: 日期={date}, 小时={hour}")
                    
                    # 查找预约记录
                    reservation = Reservation.query.filter_by(
                        gpu_uuid=gpu_uuid,
                        date=date,
                        hour=hour
                    ).first()
                    
                    if not reservation:
                        print(f"未找到预约记录")
                        continue
                        
                    # 检查是否是当前用户的预约
                    if reservation.user_id != current_user.id:
                        print(f"无权限取消其他用户的预约")
                        return jsonify({
                            'status': 'error', 
                            'message': f'您无权取消其他用户的预约'
                        }), 403
                    
                    # 删除预约
                    db.session.delete(reservation)
                    print(f"预约记录已删除")
                    
                except Exception as e:
                    print(f"处理时间槽时出错: {time_slot}, 错误: {str(e)}")
                    return jsonify({'status': 'error', 'message': f'处理时间槽时出错: {str(e)}'}), 400
        
        try:
            db.session.commit()
            print("取消预约成功")
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            print(f"保存更改时出错: {str(e)}")
            return jsonify({'status': 'error', 'message': f'保存更改时出错: {str(e)}'}), 400
            
    except Exception as e:
        print(f"取消预约时出错: {str(e)}")
        return jsonify({'status': 'error', 'message': f'取消预约时出错: {str(e)}'}), 500

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

if __name__ == '__main__':
    # 启动时检查GPU
    print("\n=== 系统启动时的GPU检查 ===")
    devices = Device.all()
    print(f"系统中共检测到 {len(devices)} 个GPU设备：")
    for device in devices:
        print(f"GPU {device.index}: {device.name}")
    print("=========================\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True) 