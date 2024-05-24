# paasau
## 介绍
paasau是跨境流量合规检测工具，接近实时查找连接进程，支持Arm Linux/Android系统运行。

```
#paasau -h  
Usage of paasau:
	-foreign
    	切换为国外车型的跨境合规检测. Declare this is foreigen car.
  -h	帮助信息. Show help information.
  -i string
    	-i eth0,wlan0 指定网卡. Specify the network interface
  -o string
    	指定日志、流量包的保存目录(默认为当前执行路径目录).
  -save
    	使能本地保存Pcap流量包(存储空间消耗大).
  -who
    	使能查找违规IP通信的进程(性能消耗大).

#国内车型
./paasau -i eth0,wlan0 -who -save
#国外车型
./paasau -i eth0,wlan0 -who -save -foreign
```
若当前机器存在跨境IP的通信，会在终端输出跨境IP及通信进程信息。




## Android使用指南
```
adb push paasau-v1.3.3_armv7 /data/local/tmp/

adb shell
su
chmod +x /data/local/tmp/paasau-v1.3.3_armv7
cd /data/local/tmp
# 挂后台运行
nohup ./paasau-v1.3.3_armv7 -i eth0 &

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

CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV -static" go build -o paasau-v1.3.3-arm64 paasau-v1.3.3.go 
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

CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV -static" go build -o paasau-armv7-v1.3.3 paasau-v1.3.3.go

```

## macOS交叉编译arm v7
```
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


sudo apt install build-essential -y

cd /tmp
export PCAPV=1.10.4
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV

apt install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi flex bison -y

./configure --host=arm-linux-gnueabi --with-pcap=linux CC=arm-linux-gnueabi-gcc
make
cd ../


wget https://dl.google.com/go/go1.22.2.linux-arm64.tar.gz
sudo tar -xvf go1.22.2.linux-arm64.tar.gz -C /usr/local

echo export PATH=$HOME/go/bin:/usr/local/go/bin:$PATH >> ~/.profile
source ~/.profile

go version

sudo apt install libpcap-dev -y

CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L./libpcap-1.10.4 -static" go build -o paasau-armv7 paasau.go 

```

## Release
1.3.2 用了embed特性，打包成一个文件就可以用啦，体积更轻量了。

1.3.3 支持多网卡，傻瓜式使用。

1.3.4 支持海外回境的合规检测。

1.3.8 设置CPU上限；优化了变量命名；对象复用，改善了一点点理论性能；强制使用中国上海时区GMT 8:00；改善程序退出机制。


## 致谢

[Hackl0us](https://github.com/Hackl0us) [GeoIP2-CN ](https://github.com/Hackl0us/GeoIP2-CN)，轻量漂亮的IP数据库

rfyiamcool [go-netflow](https://github.com/rfyiamcool/go-netflow) ，Go入门参考

