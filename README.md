# paasau

`paasau` 是一个面向车联网/嵌入式联网场景的跨境 IP 合规排查工具，用于识别设备是否访问了不符合地域策略的公网 IP。

典型用法很简单：

- 国内车型：检查是否访问了非中国大陆公网 IP
- 海外车型：检查是否访问了中国大陆公网 IP
- 实时排查：直接运行 `paasau`
- 离线复盘：运行 `paasau offline <pcap目录>`

GitHub 历史仓库为 [go1f/paasau](https://github.com/go1f/paasau)。

## 快速上手

默认入口是 `live`：

- `/path/to/paasau` 等价于 `/path/to/paasau live`
- `/path/to/paasau -who` 等价于 `/path/to/paasau live -who`
- 只有离线扫描时才需要显式写 `offline`

### 查看帮助

```bash
/path/to/paasau -h
/path/to/paasau live -h
/path/to/paasau offline -h
```

### 常用命令

实时检测：

```bash
/path/to/paasau
/path/to/paasau -policy china-car
/path/to/paasau -foreign
/path/to/paasau -who
/path/to/paasau -save
/path/to/paasau -i eth0,wlan0
/path/to/paasau -pn "adb|curl|python"
/path/to/paasau -db /path/to/mmdb/GeoIP2-CN.mmdb
```

离线检测：

```bash
/path/to/paasau offline /path/to/pcap_dump
/path/to/paasau offline -policy china-car /path/to/pcap_dump
/path/to/paasau offline -policy foreign-car /path/to/pcap_dump
/path/to/paasau offline -foreign /path/to/pcap_dump
/path/to/paasau offline -db /path/to/mmdb/GeoLite2-City-250626-V01.mmdb /path/to/pcap_dump
```

### 主要参数

- `-config`：指定配置文件，默认 `configs/default.json`
- `-policy`：指定策略名，如 `china-car` / `foreign-car`
- `-foreign`：兼容旧版本参数，等价于 `-policy foreign-car`
- `-i`：指定抓包网卡，多个网卡用逗号分隔
- `-o`：指定运行输出目录
- `-db`：指定数据库文件路径
- `-save`：保存抓到的 `.pcap`
- `-who`：启用违规连接的进程定位
- `-pn`：仅定位匹配正则的进程名

### 策略说明

- `china-car`：仅允许中国大陆目的 IP
- `foreign-car`：禁止中国大陆目的 IP

### 默认数据库

- 实时检测默认库：`assets/mmdb/GeoIP2-CN-20250318.mmdb`
- 离线检测默认库：`assets/mmdb/GeoLite2-City-250626-V01.mmdb`

### Android 使用示例

构建后把二进制推到设备：

```bash
adb shell mkdir -p /data/local/tmp/paasau
adb push /path/to/paasau /data/local/tmp/paasau/paasau
adb root
adb shell "chmod +x /data/local/tmp/paasau/paasau"
```

国内车型实时检查：

```bash
adb shell "nohup /data/local/tmp/paasau/paasau -policy china-car -who -save -o /data/local/tmp/paasau/ >/dev/null 2>&1 &"
```

海外车型实时检查：

```bash
adb shell "nohup /data/local/tmp/paasau/paasau -policy foreign-car -who -save -o /data/local/tmp/paasau/ >/dev/null 2>&1 &"
adb shell "nohup /data/local/tmp/paasau/paasau -foreign -who -save -o /data/local/tmp/paasau/ >/dev/null 2>&1 &"
```

按进程名筛查：

```bash
adb shell "nohup /data/local/tmp/paasau/paasau -policy china-car -who -pn 'curl|python|adb' -o /data/local/tmp/paasau/ >/dev/null 2>&1 &"
```

离线抓包分析：

```bash
adb root
adb shell "tcpdump -i any -w /sdcard/pcap240701.pcap"
adb pull /sdcard/pcap240701.pcap
/path/to/paasau offline .
```

## 构建

建议使用工作区内的 Go 缓存目录：

```bash
GOCACHE=$(pwd)/.gocache go build -o /path/to/paasau ./cmd/paasau
```

也可以直接使用脚本：

```bash
./scripts/build_local.sh
```

如果需要沿用 Ubuntu 容器构建流程：

```bash
./scripts/build_orb_ubuntu.sh
```

验证整个当前模块可构建：

```bash
GOCACHE=$(pwd)/.gocache go build ./...
```

## 配置文件

默认配置文件是 `configs/default.json`。

当前配置拆成三类：

- `runtime`
  - 调试开关
  - 输出目录
  - 时区
- `live`
  - 默认策略
  - MMDB 路径
  - 默认 BPF 过滤器
  - 进程定位 worker 数
  - 超时时间
  - 抓包参数
- `policies`
  - 合规策略定义
  - 通过 `mode=allowlist|denylist` 和 `countries` 表达规则

示例：

```json
{
  "policies": {
    "china-car": {
      "mode": "allowlist",
      "countries": ["CN"]
    },
    "foreign-car": {
      "mode": "denylist",
      "countries": ["CN"]
    }
  }
}
```

## 当前目录结构

```text
.
├── assets/mmdb/          # GeoIP/MMDB 数据库
├── backup/local-only/    # 本地备份，不同步 GitHub
├── cmd/paasau/           # 统一 CLI 入口
├── configs/              # 配置文件
├── dist/                 # 构建产物
├── internal/             # 核心实现
├── old/                  # 历史版本和旧资料
├── runtime/              # 日志、抓包等运行产物
├── test/                 # eBPF 实验代码（默认不参与构建）
└── README.md
```

说明：

- 老版本源码、旧日志、旧二进制、旧交叉编译目录已移动到 `backup/local-only/`，并通过 `.gitignore` 排除，不参与 GitHub 同步。
- `test/` 下的 eBPF 代码默认通过 build tag 排除，不影响当前版本的默认构建。

## 当前实现说明

### 实时检测

- 自动枚举所有处于 UP 状态的非回环网卡
- 使用可配置的 BPF 过滤器抓取 IPv4 流量
- 过滤私网、回环、多播、链路本地、广播等地址
- 基于 MMDB 读取目的 IP 国家码
- 按策略判断是否违规
- 可选保存抓包
- 可选使用 `gopsutil` 尝试定位发起连接的进程

### 离线检测

- 递归扫描 pcap 目录
- 仅处理 IPv4 目的地址
- 对同一文件中的 IP 去重
- 输出违规 IP 及国家码

## 已知限制

- 当前主要处理 IPv4，IPv6 支持不足
- 地域判断依赖离线 MMDB 数据，准确性受数据库版本影响
- 进程定位仍基于遍历进程连接表，性能和命中率都有限
- Android/嵌入式环境下的进程定位受权限和连接生命周期影响，不能保证 100% 命中
- `test/` 目录中的 eBPF 方案仍是实验状态，未纳入主流程

## 推荐后续优化

- 补 `.github/workflows` 做自动构建和发布
- 给策略配置增加 schema 校验
- 为 `live` / `offline` 增加 JSON 输出格式
- 为回归测试补充标准 pcap 样本
- 将进程归因逐步迁移到 eBPF 事件链路
