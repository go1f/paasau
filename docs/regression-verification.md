# 回归验证用例

## Live 抓包保存后由 Offline 复核异常 IP

目的：验证带 cgo/libpcap 的 live 构建可以在设备侧抓到跨境异常 IP，保存的 pcap 拉回本地后，offline 模式也能识别同一异常 IP。

环境：

- 设备：通过 adb 连接的 Android 设备，具备 root 抓包权限。
- 二进制：`dist/releases/paasau_arm-linux-gnueabihf_static`。
- 策略：`china-car`。
- 触发流量：设备侧访问 `9.9.9.9`。

步骤：

```bash
adb shell 'rm -rf /data/local/tmp/paasau-live-test && mkdir -p /data/local/tmp/paasau-live-test/out'
adb push dist/releases/paasau_arm-linux-gnueabihf_static /data/local/tmp/paasau-live-test/paasau_live
adb shell 'chmod 755 /data/local/tmp/paasau-live-test/paasau_live'

adb shell '/data/local/tmp/paasau-live-test/paasau_live -live -i any -save -policy china-car -o /data/local/tmp/paasau-live-test/out'
adb shell 'ping -c 4 -W 1 9.9.9.9'

adb pull /data/local/tmp/paasau-live-test/out /tmp/paasau-live-pull
go run ./cmd/paasau -offline -policy china-car /tmp/paasau-live-pull/out
adb shell 'rm -rf /data/local/tmp/paasau-live-test'
```

通过标准：

- live 输出包含 `OpenLive interface: any`，确认走 cgo/libpcap live 路径。
- live 输出包含 `Violated IP: 9.9.9.9 ... policy=china-car`。
- 设备侧生成 `capture_paasau_any_*.pcap`。
- 本地 offline 扫描拉回的 pcap 输出 `violated ip=9.9.9.9 country=US`。
- 不出现 `read config ... no such file`、`open geoip db ... no such file`、`live capture requires cgo/libpcap support`。

最近一次验证结果：

```text
binary:  UPX-compressed dist/releases/paasau_arm-linux-gnueabihf_static
live:    OpenLive interface: any
live:    Violated IP: 9.9.9.9 country= iface=any policy=china-car
offline: violated ip=9.9.9.9 country=US
pcap:    /tmp/paasau-upx-live-pull-9999/out/capture_paasau_any_260513_005623.pcap
```
