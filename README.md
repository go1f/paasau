# paasau_ii
## 介绍
paasau_ii是跨境流量实时分析工具，支持Arm Linux/Android系统运行。

将paasau_ii放到一个可写的目录，即可运行。
```
./paasau_ii-v1.3.3_armv7
```
若当前机器存在跨境IP的通信，会在终端输出跨境IP及通信进程信息，并输出文件：
1、跨境告警的日志，长这样：record_paasau_ii_20240112_01_25_21.log
2、外网通信流量包，长这样：capture_paasau_ii_20240112_01_25_21.pcap


## 以下是Android使用指南
```
adb push paasau_ii-v1.3.3_armv7 /data/local/tmp/

adb shell
su
chmod +x /data/local/tmp/paasau_ii-v1.3.3_armv7
cd /data/local/tmp
# 挂后台运行
nohup ./paasau_ii-v1.3.3_armv7 -i eth0 &

# 持续观察有无跨境流量
tail -f /data/local/tmp/nohup.out
```


## 交叉编译arm64
```
wget https://dl.google.com/go/go1.20.5.linux-amd64.tar.gz
sudo tar -xvf go1.20.5.linux-amd64.tar.gz
export GOROOT=/usr/local/go

cd /tmp
export PCAPV=1.10.4
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=aarch64-linux-gnu-gcc
./configure --host=aarch64-linux --with-pcap=linux
make


export PCAPV=1.10.4
export PATH=$PATH:/usr/local/go/bin

CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=armv7 CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV -static" go build -o paasau_ii-v1.3.3-arm64 paasau_ii-v1.3.3.go 
```

## 交叉编译arm v7
```
cd /tmp
export PCAPV=1.10.4
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
apt install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi

export CC=arm-linux-gnueabi-gcc
./configure --host=arm-linux-gnueabi --with-pcap=linux
make

export PCAPV=1.10.4
export PATH=$PATH:/usr/local/go/bin

CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV -static" go build -o paasau_ii-armv7-v1.3.3 paasau_ii-v1.3.3.go

```


## Release
1.3.2 用了embed特性+UPX，打包成一个文件就可以用啦，体积更轻量了。
1.3.3 支持多网卡，傻瓜式使用。
1.3.4 支持海外车型的合规检测。