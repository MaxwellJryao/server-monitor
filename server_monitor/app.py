from flask import Flask, render_template, jsonify
import psutil
import time
from datetime import datetime
from nvitop import Device, GpuProcess, HostProcess

app = Flask(__name__)

def get_system_info(verbose=False):
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
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
        'disk': {
            'total': int(disk.total),
            'used': int(disk.used),
            'free': int(disk.free),
            'percent': float(disk.percent)
        },
        'gpus': gpus
    }
    
    if verbose:
        print(f"返回数据中包含 {len(gpus)} 个GPU信息")
    return result

@app.route('/')
def index():
    return render_template('index.html')

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