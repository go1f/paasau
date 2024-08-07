# paasau
paasau是跨境流量合规检测工具，接近实时查找连接进程，支持Arm Linux/Android系统运行。

```
#paasau -h
Usage of paasau:
  --foreign
            切换为国外车型的跨境合规检测. Declare this is foreigen car.
  -h        帮助信息. Show help information.
  -i string
            -i eth0,wlan0 指定网卡，默认抓取所有Open网卡. Specify the network interface
  -o string
            指定日志、流量包的保存目录(默认为当前执行路径目录).
  -pn string
            -pn <processName>. 仅检查指定的进程(支持正则匹配). Specify the process name
  --save
            使能本地保存Pcap流量包(存储空间消耗大).
  --who
            使能查找违规IP通信的进程(性能消耗大).

#国内车型
/path/to/paasau -i eth0,wlan0 -who -save
#国外车型
/path/to/paasau -i eth0,wlan0 -who -save -foreign
```
若当前机器存在跨境IP的通信，会在终端输出跨境IP及通信进程信息。



## Android使用指南

1. 推工具到Android设备，举例目录为/data/local/tmp/paasau

```Bash
# 创建目录
adb shell mkdir /data/local/tmp/paasau
# 推工具到指定目录
adb push paasau /data/local/tmp/paasau/paasau
```

2. 

```Bash
adb root
adb shell "chmod +x /data/local/tmp/paasau/paasau"

#国内车型
adb shell  "nohup /data/local/tmp/paasau/paasau --who --save -o /data/local/tmp/paasau/ > /dev/null 2>&1 &"

#国外车型，国外车型需使用-foreign参数
adb shell "nohup /data/local/tmp/paasau/paasau --foreign --who --save -o /data/local/tmp/paasau/ > /dev/null 2>&1 &"

#筛选包含cloud名称的进程
adb shell "nohup /data/local/tmp/paasau/paasau --who -pn cloud --save -o /data/local/tmp/paasau/ > /dev/null 2>&1 &"
```

3. 持续观察有无跨境流量

```bash
adb shell "tail -f /data/local/tmp/paasau/nohup.out"
```



3. 终止运行

```Bash
adb shell "ps -ef |grep paasau"

adb shell "kill <PID>"
```



## 离线版本

1. tcpdump抓取流量

```Python
adb root
adb shell
tcpdump -i any -w /sdcard/pcap240701.pcap
```

2. 拖回本地，扫描。

```Python
adb pull /sdcard/pcap240701.pcap
paasau_offline.exe pcap240701.pcap
```




## 交叉编译ARM64
```
wget https://dl.google.com/go/go1.20.5.linux-amd64.tar.gz
sudo tar -xvf go1.20.5.linux-amd64.tar.gz
export GOROOT=/usr/local/go

export PCAPV=1.10.4
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
mkdir aarch64
tar -zxvf libpcap-$PCAPV.tar.gz -C aarch64
cd aarch64/libpcap-$PCAPV
export CC=aarch64-linux-gnu-gcc
./configure --host=aarch64-linux --with-pcap=linux --disable-dbus
make
cd ../../

export PCAPV=1.10.4
export PATH=$PATH:/usr/local/go/bin
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CGO_LDFLAGS="-L./aarch64/libpcap-$PCAPV -static" go build -o paasau_aarch64 paasau.go

upx paasau_aarch64
```

## 交叉编译ARMv7
```
cd /tmp
export PCAPV=1.10.4
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
mkdir armv7
tar -zxvf libpcap-$PCAPV.tar.gz -C armv7
cd armv7/libpcap-$PCAPV
apt install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi

export CC=arm-linux-gnueabi-gcc
./configure --host=arm-linux-gnueabi --with-pcap=linux --disable-dbus
make
cd ../../

export PCAPV=1.10.4
export PATH=$PATH:/usr/local/go/bin

CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L./armv7/libpcap-$PCAPV -static" go build -o paasau_aarch64 paasau.go

upx paasau_aarch64
```

## MacOS交叉编译ARMv7
```
cd paasau

brew install orb

orb

sudo bash -c "cat << EOF > /etc/apt/sources.list && apt update 
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ jammy main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ jammy main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ jammy-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ jammy-backports main restricted universe multiverse
deb http://ports.ubuntu.com/ubuntu-ports/ jammy-security main restricted universe multiverse
# deb-src http://ports.ubuntu.com/ubuntu-ports/ jammy-security main restricted universe multiverse
EOF"

sudo apt install build-essential upx -y

export PCAPV=1.10.4
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz -C armv7

cd armv7/libpcap-$PCAPV

sudo apt install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi flex bison -y

./configure --host=arm-linux-gnueabi --with-pcap=linux CC=arm-linux-gnueabi-gcc --disable-dbus
make
cd ../../


wget https://dl.google.com/go/go1.22.2.linux-arm64.tar.gz
sudo tar -xvf go1.22.2.linux-arm64.tar.gz -C /usr/local

echo export PATH=$HOME/go/bin:/usr/local/go/bin:$PATH >> ~/.profile
source ~/.profile

go version

sudo apt install libpcap-dev -y

CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L./armv7/libpcap-1.10.4 -static" go build -o paasau_armv7 paasau.go 

upx paasau_armv7
```






## 致谢

[Hackl0us](https://github.com/Hackl0us) [GeoIP2-CN ](https://github.com/Hackl0us/GeoIP2-CN)，轻量漂亮的IP数据库

