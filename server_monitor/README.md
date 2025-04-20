# 服务器硬件监控系统

这是一个实时监控服务器硬件状态的Web应用，可以显示CPU、内存、磁盘和GPU的使用情况。

## 功能特点

- 实时监控CPU使用率
- 实时监控内存使用情况
- 实时监控磁盘使用情况
- 实时监控GPU使用情况（如果可用）
  - GPU利用率
  - GPU温度
  - GPU功率使用
  - GPU风扇速度
  - GPU内存使用情况
- 使用图表直观显示数据
- 自动更新数据（每2秒更新一次）

## 安装要求

- Python 3.6+
- pip（Python包管理器）
- NVIDIA驱动（用于GPU监控）

## 安装步骤

1. 克隆或下载本项目到本地

2. 安装依赖包：
```bash
pip install -r requirements.txt
```

3. 安装nvitop（如果尚未安装）：
```bash
pip install nvitop
```

## 运行方法

1. 进入项目目录：
```bash
cd server_monitor
```

2. 运行Flask应用：
```bash
python app.py
```

3. 在浏览器中访问：
```
http://localhost:5000
```

## 注意事项

- 确保系统已安装Python和pip
- 如果要监控GPU，需要确保系统已安装NVIDIA驱动和nvitop
- 默认端口为5000，如需修改可在app.py中更改
- nvitop需要NVIDIA驱动支持，确保驱动已正确安装

## 技术栈

- 后端：Python + Flask
- 前端：HTML + JavaScript + Chart.js
- 系统监控：psutil + nvitop
- UI框架：Bootstrap 5 