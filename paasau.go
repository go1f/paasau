package main

import (
	"log"
	"time"
	"fmt"
	"embed"
	"net"
	"io"
	"os"
	// "os/exec"
	"os/signal"
	"syscall"
	"flag"
	"strings"
	"runtime"
	// "sync"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/oschwald/geoip2-golang"
	"github.com/shirou/gopsutil/process"
)


var(
	programName string
	//geoipBytes []byte
	//go:embed GeoIP2-CN-20240421.mmdb
	staticFiles embed.FS
	geoIP2CNReader *GeoIP2CNReader
	foreignFlag bool
	interfaceFlag string
	// normalIPs map[string]bool
)


func init() {
	
	// fmt.Println("Timezone fix.")
	// fixTimeZone
	// China Time. Asia/Shanghai. GMT 8:00	
	time.Local = time.FixedZone("GMT", 8*3600) 

}


func main() {

	programName = "paasau_ii"

	setUsage()

	start()

}

func start(){
	var err error

	timeString := time.Now().Format("060102_150405")

	runtime.GOMAXPROCS(4)

	geoIP2CNReader, _ = newGeoIP2CNReader()

	// 初始化日志
	logFs, err := os.Create(fmt.Sprintf("result_%v_%v.log", programName, timeString))
	if err != nil {
		log.Fatalf("Log file create: %v", err)
	}
	defer logFs.Close()

	// 设置日志输出到终端和文件
	log.SetOutput(io.MultiWriter(os.Stdout, logFs))

	// normalIPs = make(map[string]bool)

	// 提取网卡名
	interfaces := getInterfaces()

	for _, iface := range interfaces {
		
		go capture(iface)

	}



	waitExit()
}


func waitExit(){
	// 捕获 Ctrl+C 信号
	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	//等待信号
	<-c

	// time.Sleep(3 * time.Second)

	// fmt.Println("Start stopping violation detection...")

	fmt.Println("Byebye...")
	fmt.Println()
}


func setUsage() {

	var helpFlag bool
	// var backgroundFlag bool
	flag.BoolVar(&helpFlag, "h", false, "帮助信息. Show help information.")
	// flag.BoolVar(&backgroundFlag, "b", false, "后台运行. Run background.")
	flag.StringVar(&interfaceFlag, "i", "", "-i eth0,wlan0 指定网卡. Specify the network interface")
	//默认检测国内车型
	flag.BoolVar(&foreignFlag, "foreign", false, "切换为国外车型的跨境合规检测. Declare this is foreigen car.")

	// 解析命令行参数
	flag.Parse()


	// -h 参数，输出帮助信息
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if foreignFlag == false {
		fmt.Println("默认检测国内车型IP合规. 可使用 -h 参数获取帮助详情.")
		fmt.Println("IP compliance detection of China models by default. Please use the -h parameter to get more help.")
	} else{
		fmt.Println("脚本正在检测国外车型IP合规.")
		fmt.Println("Now checking IP compliance of foreign models.")
	}

	// if backgroundFlag {
	// 	_, err := syscall.Setsid()
	// 	if err != nil {
	// 		fmt.Println("切换为后台运行失败:", err)
	// 		os.Exit(1)
	// 	}

	// 	// args := strings.Join(os.Args, " ")
	// 	// args = strings.Replace(args, " -b", "", -1)
	// 	// fmt.Println(args)

	// 	// cmd := exec.Command(args)
	// 	// cmd.SysProcAttr = &syscall.SysProcAttr{
	// 	// 	Setsid: true,
	// 	// }

	// 	// err := cmd.Start()
	// 	// if err != nil {
	// 	// 	log.Fatal("Failed to start process:", err)
	// 	// 	// return
	// 	// }

	// 	// fmt.Println("Process ID:", cmd.Process.Pid)
	// 	// os.Exit(0)
	// }




}

func getInterfaces() []string {
	var IfaceNames []string

	if( len(interfaceFlag)!=0 ){
		IfaceNames = strings.Split(interfaceFlag, ",")
	} else {
		
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("net.Interfaces(): %v", err)
		}

		// var IfaceNames []string
		for _, iface := range interfaces {
			// fmt.Println(iface.Name)

			// 筛选UP状态的网卡
			// syscall.IFF_UP, syscall.IFF_RUNNING refer:https://go.dev/src/net/interface_linux.go
			if iface.Flags & syscall.IFF_UP != 0 {
				//去掉环回地址lo网卡
				if strings.HasPrefix(iface.Name, "lo") == false {
					IfaceNames = append(IfaceNames, iface.Name)

				}
			}
			
		}
	}

	return IfaceNames
}

func capture(ifaceName string){

	fmt.Println("开启 " + ifaceName + " 网卡抓包。")


	// 打开网络设备
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("OpenLive: %v",err)
	}

	// 保存文件
	timeString := time.Now().Format("060102_1504_05")
	fileName := fmt.Sprintf("capture_%v_%v_%v.pcap", programName, ifaceName, timeString)
	pcapFile, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("pcap, os.Create: %v", err)
	}

	pcapWriter := pcapgo.NewWriter(pcapFile)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("pcapWriter.WriteFileHeader: %v", err)
	}

	defer handle.Close()
	defer pcapFile.Close()

	// 设置过滤器
	err = handle.SetBPFFilter("not ((dst net 192.168.0.0/16 or dst net 172.16.0.0/12 or dst net 10.0.0.0/8 or dst net 255.255.255.255 or dst net 169.254.0.0/16 or dst net 224.0.0.0/4 or dst net 127.0.0.0/8) and (src net 192.168.0.0/16 or src net 172.16.0.0/12 or src net 10.0.0.0/8 or src net 169.254.0.0/16 or src net 127.0.0.0/8))")
	if err != nil {
		log.Fatal("SetBPFFilter: %v",err)
	}

	// 开始抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 保存
		if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket: %v", err)
		}
		// print(1)
		go prasePacket(packet)
	}
}



func prasePacket(packet gopacket.Packet) {
	// print(2)
	// 解析IP数据包
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {

		ipPacket, _ := ipLayer.(*layers.IPv4)

		// SrcIP := ipPacket.SrcIP.String()
		dstIP := ipPacket.DstIP.String()

		// 记录合规IP，不再重复检查
		// if normalIPs[DstIP] == false && checkViolationIP(DstIP) {

		// 判断目的地址是否合规，合规结果为True则跳过
		if checkViolationIP(dstIP) {
			// normalIPs[DstIP] = true
			return
		}

		log.Printf("Found Violation IP: %s\n", dstIP)

		// 查找发起连接的进程
		findProcess(dstIP)
		
	}
}


type GeoIP2CNReader struct {
	reader	*geoip2.Reader
	// lock	sync.Mutex
}

func newGeoIP2CNReader() (*GeoIP2CNReader, error){

	// 初始化IP MMDB数据库
	bytes, err := staticFiles.ReadFile("GeoIP2-CN-20240421.mmdb")
	if err != nil {
		log.Fatal("Failed to read MMDB:", err)
	}

	reader, err := geoip2.FromBytes(bytes) 
	if err != nil {
		log.Fatal(err)
	}
	// defer reader.Close()

	return &GeoIP2CNReader{
		reader: reader,
	}, err
}

func (rd *GeoIP2CNReader) isChinaIP(netIP net.IP) bool {
	// rd.lock.Lock()
	// defer rd.lock.Unlock()

	country, err := rd.reader.Country(netIP)
	if err != nil {
		log.Println("rd.reader.Country: ", err)
	}

	// fmt.Println(country.Country.Names["en"])

	return country.Country.Names["en"] == "China"
}

//True合规，False违规
func checkViolationIP(ip string) bool {

	// 排除响应包或外部主动请求的包
	netIP := net.ParseIP(ip)
	if netIP.IsPrivate() || netIP.IsLoopback() || netIP.IsMulticast() || 
	netIP.IsLinkLocalUnicast() || netIP.IsUnspecified() || ip=="255.255.255.255" {
		// fmt.Printf("Skip Src IP: %s.\n", sip)
		return true
	}

	// db, err := geoip2.FromBytes(geoipBytes) 
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer db.Close()
	
	// record1, err := db.Country(netIP)
	// if err != nil {
	// 	log.Println(err)
	// }

	// 判断目的地址是否合规
	// if foreignFlag == false{
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

	// if record1.Country.Names["en"] == "China"{
	if geoIP2CNReader.isChinaIP(netIP){
		//中国IP && 国内车型 = 合规
		if foreignFlag == false{
			fmt.Printf("Skip CN IP: %s\n", ip)
			return true
	}} else{
		//外国IP && 国外车型 = 合规
		if foreignFlag == true{
			fmt.Printf("Skip foreign IP: %s\n", ip)
			return true
	}}
	//其他情况，不合规
	return false
}

func findProcess(ip string) {
	// 获取进程信息
	// todo: SYN的包查不到进程，遍历查询太慢了
	processes, _ := process.Processes()
	for _, proc := range processes {
		conns, _ := proc.Connections()
		for _, conn := range conns {
			if conn.Raddr.IP == ip {
				pid := proc.Pid
				processName, _ := proc.Name()
				processPath, _ := proc.Exe()

				log.Printf("Violation IP's process=%s(%s), pid=%d, src=%s:%d, dst=%s:%d\n", processName, processPath, pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)

			}
		}
	}
}
