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
	// "runtime"
	"context"
	"regexp"
	// "path/filepath"
	"sync"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/oschwald/geoip2-golang"
	"github.com/shirou/gopsutil/process"
)


var(
    debug = true
	programName = "paasau"
	//geoipBytes []byte
	//go:embed GeoIP2-CN-20240804.mmdb
	staticFiles embed.FS
	activeSearches sync.Map
    workerSemaphore = make(chan struct{}, 2) // 限制最多 5 个并发 worker
	geoIP2CNReader *GeoIP2CNReader
	foreignFlag bool
	interfaceFlag string
	savePcapFlag bool
	findProcessFlag bool
	regexProcessName *regexp.Regexp
	outputDir string

	// normalIPs map[string]bool
)

var (
    debugLogger *log.Logger
    infoLogger  *log.Logger
    errorLogger *log.Logger
)



func init() {
	
	// fmt.Println("Timezone fix.")
	// fixTimeZone
	// China Time. Asia/Shanghai. GMT 8:00	
	time.Local = time.FixedZone("GMT", 8*3600) 


	initParam()

	// 初始化日志
	// 切换debug模式
    initLoggers(debug)

}


func main() {



	start()

}

func start(){

	// runtime.GOMAXPROCS(2)



    
	geoIP2CNReader, _ = newGeoIP2CNReader()


	// executablePath, err := os.Executable()
	// executableDir = filepath.Dir(executablePath)
	// print(executableDir)

	// normalIPs = make(map[string]bool)

	// 提取网卡名
	interfaces := getInterfaces()

	for _, iface := range interfaces {
		
		go capture(iface)

	}

	waitToExit()
}


func waitToExit(){
	// 捕获 Ctrl+C 信号
	c := make(chan os.Signal, 1)

	// signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	signal.Notify(c, os.Interrupt)

	//等待信号
	<-c

	// time.Sleep(3 * time.Second)

	// fmt.Println("Start stopping violation detection...")

	fmt.Println("Byebye...")
	fmt.Println()
}


func initLoggers(debug bool) {
    if debug {
        debugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)
    } else {
        debugLogger = log.New(os.Stdout, "", 0) // 不输出debug信息
    }
    infoLogger = log.New(os.Stdout, "", log.Ldate|log.Ltime)

    // errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)


	timeString := time.Now().Format("060102_150405")

	f, err := os.Create(outputDir+fmt.Sprintf("result_%v_%v.log", programName, timeString))
	f2, err := os.Create(outputDir+fmt.Sprintf("debug_%v_%v.log", programName, timeString))
	if err != nil {
		debugLogger.Fatalf("Log file create: %v", err)
	}
	// 设置日志输出到终端和文件
	infoLogger.SetOutput(io.MultiWriter(os.Stdout, f))
	debugLogger.SetOutput(io.MultiWriter(os.Stdout, f2))
	// defer logFs.Close()


}

func initParam() {

	var helpFlag bool
	var processNameFlag string
	// var backgroundFlag bool
	flag.BoolVar(&helpFlag, "h", false, "帮助信息. Show help information.")
	// flag.BoolVar(&backgroundFlag, "b", false, "后台运行. Run background.")
	//默认检测国内车型
	flag.BoolVar(&foreignFlag, "foreign", false, "切换为国外车型的跨境合规检测. Declare this is foreigen car.")
	flag.BoolVar(&savePcapFlag, "save", false, "使能本地保存Pcap流量包(存储空间消耗大).")
	flag.StringVar(&outputDir, "o", "", "指定日志、流量包的保存目录(默认为当前执行路径目录).")	
	flag.BoolVar(&findProcessFlag, "who", false, "使能查找违规IP通信的进程(性能消耗大).")
	flag.StringVar(&interfaceFlag, "i", "", "-i eth0,wlan0 指定网卡，默认抓取所有Open网卡. Specify the network interface")
	flag.StringVar(&processNameFlag, "pn", "", "-pn <processName>. 仅检查指定的进程(支持正则匹配). Specify the process name")

	// 解析命令行参数
	flag.Parse()


	// -h 参数，输出帮助信息
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if len(outputDir) > 0 {
		outputDir = outputDir + "/"
	}

	if foreignFlag == false {
		// fmt.Println("默认检测国内车型IP合规. 可使用 -h 参数获取帮助详情.")
		fmt.Println("IP compliance detection of China models by default. Please use the -h parameter to get more help.")
	} else{
		// fmt.Println("脚本正在检测国外车型IP合规.")
		fmt.Println("Now checking IP compliance of foreign models.")
	}

	if processNameFlag != "" {
		findProcessFlag = true
		regexProcessName = regexp.MustCompile("(?i)" + processNameFlag)
		fmt.Printf("******** Attention! Now only check of '%s' like process. If you wanna check ALL process, don't use -pn parameter.\n", processNameFlag)
	}

}


func getInterfaces() []string {
	var IfaceNames []string

	if( len(interfaceFlag)!=0 ){
		IfaceNames = strings.Split(interfaceFlag, ",")
	} else {
		
		interfaces, err := net.Interfaces()
		if err != nil {
			debugLogger.Fatalf("net.Interfaces(): %v", err)
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

	// fmt.Println("开启 " + ifaceName + " 网卡抓包。")

	fmt.Println("Openlive " + ifaceName + " interface.")


	// 打开网络设备
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("OpenLive: %v",err)
		return
	}
	defer handle.Close()

	var pcapWriter *pcapgo.Writer
	// 保存文件
	if savePcapFlag {
		timeString := time.Now().Format("060102_1504_05")
		fileName := fmt.Sprintf("capture_%v_%v_%v.pcap", programName, ifaceName, timeString)
		pcapFile, err := os.Create(outputDir+fileName)
		if err != nil {
			debugLogger.Fatalf("pcap, os.Create: %v", err)
		}

		pcapWriter = pcapgo.NewWriter(pcapFile)
		if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			debugLogger.Fatalf("pcapWriter.WriteFileHeader: %v", err)
		}

		defer pcapFile.Close()
	}

	// 设置过滤器
	err = handle.SetBPFFilter("ip and (not net 172.168.1.0/31) and not ((dst net 192.168.0.0/16 or dst net 172.16.0.0/12 or dst net 10.0.0.0/8 or dst net 255.255.255.255 or dst net 169.254.0.0/16 or dst net 224.0.0.0/4 or dst net 127.0.0.0/8) and (src net 192.168.0.0/16 or src net 172.16.0.0/12 or src net 10.0.0.0/8 or src net 169.254.0.0/16 or src net 127.0.0.0/8))")
	if err != nil {
		debugLogger.Fatal("SetBPFFilter: %v",err)
	}

	// 开始抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
		// 保存
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				debugLogger.Fatalf("pcap.WritePacket: %v", err)
			}
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

		infoLogger.Printf("Violated IP: %s\n", dstIP)

		if findProcessFlag {
			// 查找发起连接的进程
			// findProcess(dstIP)	
			// 查找发起连接的进程
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel() // 确保所有路径都调用cancel

			findProcessWorker(ctx, dstIP)
		}
		
	}
}


type GeoIP2CNReader struct {
	reader	*geoip2.Reader
	// lock	sync.Mutex
}

func newGeoIP2CNReader() (*GeoIP2CNReader, error){

	// 初始化IP MMDB数据库
	bytes, err := staticFiles.ReadFile("GeoIP2-CN-20240804.mmdb")
	if err != nil {
		debugLogger.Fatal("Failed to read MMDB:", err)
	}

	reader, err := geoip2.FromBytes(bytes) 
	if err != nil {
		debugLogger.Fatal(err)
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
		debugLogger.Fatalf("rd.reader.Country: ", err)
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
		// debugLogger.Printf("Skip Src IP: %s.\n", sip)
		// debugLogger.Printf("Skip localnetwork IP: %s\n", ip)
		return true
	}

	// if record1.Country.Names["en"] == "China"{
	// 复用对象，减少资源消耗
	if geoIP2CNReader.isChinaIP(netIP){
		//中国IP && 国内车型 = 合规
		if foreignFlag == false{
			debugLogger.Printf("Skip CN IP: %s\n", ip)
			return true
	}} else{
		//外国IP && 国外车型 = 合规
		if foreignFlag == true{
			debugLogger.Printf("Skip foreign IP: %s\n", ip)
			return true
	}}
	//其他情况，不合规
	return false
}

func findProcessWorker(ctx context.Context, ip string) {
	// 检查 IP 是否已经在搜索中
    if _, exists := activeSearches.LoadOrStore(ip, true); exists {
        debugLogger.Printf("Skip duplicated searching: %s ", ip)
        return
    }
    defer activeSearches.Delete(ip)

    // 获取一个 worker 槽位
    select {
    case workerSemaphore <- struct{}{}:
        defer func() { <-workerSemaphore }()
    case <-ctx.Done():
        return
    default:
    	return
    }


	// 创建一个channel来发送结果
    resultCh := make(chan string)

	start := time.Now()
	// wg.Add(1)

    // 在一个新的goroutine中执行实际的任务
    go func() {
    	// defer wg.Done()
    	defer close(resultCh)
        // findProcess(ip)

        // 获取进程信息
		processes, _ := process.Processes()
		for _, proc := range processes {
			// 若指定了进程
			if regexProcessName != nil {
				pn,_ := proc.Name()
				if !regexProcessName.MatchString(pn){
					continue
				}
			}
			conns, _ := proc.Connections()
			for _, conn := range conns {
				if conn.Raddr.IP == ip {
					pid := proc.Pid
					processName, _ := proc.Name()
					processPath, _ := proc.Exe()

					// infoLogger.Printf("Violated process: %s(%s), pid=%d, src=%s:%d, dst=%s:%d\n", processName, processPath, pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)
					
					resultCh <- fmt.Sprintf("Violated process: %s(%s), pid=%d, src=%s:%d, dst=%s:%d\n", processName, processPath, pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)
					
					// 不再往下查找
					return 
				}
			}

			select {
	            case <-ctx.Done():
	                // resultCh <- fmt.Sprintf("Miss process matched (Overtime): %s", ip)
	                return
	            default:
                // 继续执行
            }
		}

		resultCh <- fmt.Sprintf("Miss process matched: %s", ip)

    }()

    // 使用select来处理任务完成或超时
    select {
        case processResult := <-resultCh:
			elapsed := time.Since(start)
			infoLogger.Printf(processResult)
					
			debugLogger.Printf("Processfinding costs %v\n", elapsed)
          	// 任务在超时之前完成
          	return
        case <-ctx.Done():
        	// 上下文被取消（可能是因为超时）
        	elapsed := time.Since(start)
			debugLogger.Printf("Overtime matching process %v\n", elapsed)
			
          	// 任务超时
        	return
     }
}




// func findProcess(ip string) {
// 	// 获取进程信息
// 	processes, _ := process.Processes()
// 	for _, proc := range processes {
// 		conns, _ := proc.Connections()
// 		for _, conn := range conns {
// 			if conn.Raddr.IP == ip {
// 				pid := proc.Pid
// 				processName, _ := proc.Name()
// 				processPath, _ := proc.Exe()

// 				log.Printf("Violation IP's process=%s(%s), pid=%d, src=%s:%d, dst=%s:%d\n", processName, processPath, pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)

// 			}
// 		}
// 	}
// }
