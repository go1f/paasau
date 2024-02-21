package main

import (
	"fmt"
	"io"
	"embed"
	"os/exec"
	// "io/fs"
	// "io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"flag"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/oschwald/geoip2-golang"
	"github.com/shirou/gopsutil/process"
)

//go:embed IP-Database-Country-CN.mmdb
var staticFiles embed.FS
var program_name string
var db_file []byte
var foreigncarFlag bool

func main() {
	program_name = "paasau_ii"

	usage_init()
	logf := log_init()
	db_init()
	pcapf, pcapw := pcap_init()
	// handle := live_init(dev1)
	ctrl_c_init(pcapf, logf)
	// ctrl_c_init(pcapf, logf, handle)

	cmd := exec.Command("sh", "-c", "ip link show up")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("执行命令出错:", err)
		return
	}

	// 解析命令输出，提取网卡名
	interfaces := parseInterfaces(string(output))

	for _, iface := range interfaces {
		fmt.Println("已开启 "+iface+" 网卡抓包。")
		go go_capture(iface, pcapw)

	}


	for {}


}

func parseInterfaces(output string) []string {
	var interfaces []string

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// 解析网卡名
		if strings.Contains(line, "UP") {
			parts := strings.Split(line, ":")
			iface := strings.TrimSpace(parts[1])
			if(iface != "lo"){
				// fmt.Println(iface)
				interfaces = append(interfaces, iface)
			}
		}
	}

	return interfaces
}

func go_capture(iface string, pcapw *pcapgo.Writer){

	// 打开网络设备
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	// defer handle.Close()

	// 设置过滤器
	err = handle.SetBPFFilter("not ((dst net 192.168.0.0/16 or dst net 172.16.0.0/12 or dst net 10.0.0.0/8 or dst net 255.255.255.255 or dst net 169.254.0.0/16 or dst net 224.0.0.0/4) and (src net 192.168.0.0/16 or src net 172.16.0.0/12 or src net 10.0.0.0/8 or src net 169.254.0.0/16))")
	if err != nil {
		log.Fatal(err)
	}

	// 开始抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 保存
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
		go check_process(packet)
	}
}

// func usage_init() string {
func usage_init() {
	var helpFlag bool
	flag.BoolVar(&helpFlag, "h", false, "帮助信息。 Show help information.")
	// interfaceFlag := flag.String("i", "", "Please specify the network interface")
	//默认检测国内车型
	flag.BoolVar(&foreigncarFlag, "foreign", false, "添加此参数检测国外车型。 Declare this is foreigen car.")

	// 解析命令行参数
	flag.Parse()

	if foreigncarFlag == false {
		fmt.Println("脚本默认用于国内车型的IP合规检测，如需检测国外车型，请使用-h参数查看帮助。\nThe script is used for IP compliance detection of domestic models by default. If you need to detect foreign models, please use the -h parameter to view help.")
	} else{
		fmt.Println("脚本正在检测国外车型的IP合规。\nThe script is checking the IP compliance of foreign models.")
	}


	// 如果设置了 -h 参数，则输出帮助信息
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	// return *foreigncarFlag
}

func ctrl_c_init(pcapf *os.File, logf *os.File){

// func ctrl_c_init(pcapf *os.File, logf *os.File, handle *pcap.Handle){

	// 捕获 Ctrl+C 信号并停止抓包
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		// handle.Close()
		pcapf.Close()
		logf.Close()
		log.Println("Stopping packet capture...")
	}()
}

func db_init() {
	var errdb error
	db_file, errdb = staticFiles.ReadFile("IP-Database-Country-CN.mmdb")
	if errdb != nil {
		fmt.Println("Failed to read file:", errdb)
		os.Exit(1)
	}
}

func log_init() *os.File {
	timeString := time.Now().Format("20060102_15_04_05")
	// 创建一个日志文件
	file, err := os.Create(fmt.Sprintf("record_%v_%v.log", program_name, timeString))
	if err != nil {
		log.Fatal(err)
	}

	// 设置日志输出到终端和文件
	log.SetOutput(io.MultiWriter(os.Stdout, file))

	return file
}

func pcap_init() (*os.File, *pcapgo.Writer) {
	// 保存文件
	timeString := time.Now().Format("20060102_15_04_05")
	f, err := os.Create(fmt.Sprintf("capture_%v_%v.pcap", program_name, timeString))
	if err != nil {
		log.Fatal(err)
	}
	// defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	return f, pcapw
}

func live_init(dev1 string) *pcap.Handle{

	// 打开网络设备
	handle, err := pcap.OpenLive(dev1, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// 设置过滤器
	err = handle.SetBPFFilter("not ((dst net 192.168.0.0/16 or dst net 172.16.0.0/12 or dst net 10.0.0.0/8 or dst net 255.255.255.255 or dst net 169.254.0.0/16 or dst net 224.0.0.0/4) and (src net 192.168.0.0/16 or src net 172.16.0.0/12 or src net 10.0.0.0/8 or src net 169.254.0.0/16))")
	if err != nil {
		log.Fatal(err)
	}


	return handle
}

//True合规，False违规
func check_violation_ip(ip string) bool {
	db, err := geoip2.FromBytes(db_file) 
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	dip := net.ParseIP(ip)
	// fmt.Printf("Destination IP: %s\n", ip)
	record1, err := db.Country(dip)
	// db.Close()
	if err != nil {
		log.Println(err)
	}

	// 判断目的地址是否合规
	// if foreigncarFlag == false{
	// 	//国内车型中国境内IP则合规
	// 	if record1.Country.Names["en"] == "China" {
	// 		fmt.Printf("Skip CN Dst IP: %s\n", dip)
	// 		return true
	// }} else{
	// 	//国外车型国外IP则合规
	// 	if record1.Country.Names["en"] != "China" {
	// 		fmt.Printf("Skip Foreign Dst IP: %s\n", dip)
	// 		return true
	// }}

	if record1.Country.Names["en"] == "China"{
		//中国IP && 国内车型 = 合规
		if foreigncarFlag == false{
			fmt.Printf("Skip CN Dst IP: %s\n", dip)
			return true
	}} else{
		//外国IP && 国外车型 = 合规
		if foreigncarFlag == true{
			fmt.Printf("Skip Foreign Dst IP: %s\n", dip)
			return true
	}}
	//其他情况，不合规
	return false
}

func check_process(packet gopacket.Packet) {
	// 解析IP数据包
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {

		ipPacket, _ := ipLayer.(*layers.IPv4)

		srcIP := ipPacket.SrcIP.String()
		dstIP := ipPacket.DstIP.String()


		// 排除响应包或外部主动请求的包
		sip := net.ParseIP(srcIP)
		if !sip.IsPrivate() && !sip.IsLoopback() && !sip.IsLinkLocalUnicast() {
			// fmt.Printf("Skip Src IP: %s.\n", sip)
			return
		}

		// 判断目的地址是否合规，合规结果为True则跳过
		if check_violation_ip(dstIP) {
			return
		}


		// log.Println("-------------Foreign IP Warning-------------")
		log.Printf("Found Violation IP: %s\n", dstIP)
		// for key := range record.Country.Names {
		// 	fmt.Println(key)
		// }
		// fmt.Printf("Country name: %v\n", record.Country.Names["en"])
		// fmt.Println("-------------Foreign IP Warning-------------")
		// if record.Country.Names["en"] == "China" {
		// 	fmt.Println("Skip China.")
		// 	continue
		// }
		// double check

		// log.Println()
		// 获取进程信息 SYN的包查不到进程，遍历查询太慢了
		processes, _ := process.Processes()
		for _, proc := range processes {
			conns, _ := proc.Connections()
			for _, conn := range conns {
				if conn.Raddr.IP == dstIP {
					pid := proc.Pid
					processName, _ := proc.Name()
					processPath, _ := proc.Exe()

					log.Printf("Violation IP Process:  %s, PID: %d, Path: %s, Source: %s:%d, Destination: %s:%d\n", processName, pid, processPath, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)

				}
				// } else {
				// 	log.Println("Not Found the Process, Source: %s, Destination: %s\n", srcIP, dstIP)
				// }
			}
		}
	}
}
