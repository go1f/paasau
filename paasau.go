package main

import (
	"log"
	"time"
	"fmt"
	"embed"
	"net"
	"io"
	"os"
	"os/signal"
	"syscall"
	"flag"
	"strings"
	"runtime"
	"sync"
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/oschwald/geoip2-golang"
	"github.com/shirou/gopsutil/process"
)


const violationIPTimeout = 4 * time.Second // 3秒超时时间
const maxGoroutineNum = 3

var(
	programName = "paasau"
	Version = "V16"
	databaseVersion = "GeoIP2-CN-20240523"
	//go:embed GeoIP2-CN-20240523.mmdb
	staticFiles embed.FS
	geoIP2CNReader *GeoIP2CNReader
	foreignFlag bool
	interfaceFlag string
	savePcapFlag bool
	findProcessFlag bool
	outputDir string

	workerPool *WorkerPool
	violationIPStack *ViolationIPStack

)

type ViolationIPEntry struct {
    IP         string
    EnqueuedAt time.Time
}

type ViolationIPStack struct {
    entries []ViolationIPEntry
    timeout time.Duration
    mutex   sync.Mutex
}

func NewViolationIPStack(timeout time.Duration) *ViolationIPStack {
    return &ViolationIPStack{
        entries: make([]ViolationIPEntry, 0),
        timeout: timeout,
    }
}

func (s *ViolationIPStack) Push(ip string) {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    s.entries = append(s.entries, ViolationIPEntry{
        IP:         ip,
        EnqueuedAt: time.Now(),
    })
}

func (s *ViolationIPStack) Pop() string {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    s.removeExpired()

    if len(s.entries) == 0 {
        return ""
    }

    ip := s.entries[len(s.entries)-1].IP
    s.entries = s.entries[:len(s.entries)-1]
    return ip
}

func (s *ViolationIPStack) removeExpired() {
    now := time.Now()
    validCount := 0

    for _, entry := range s.entries {
        if now.Sub(entry.EnqueuedAt) < s.timeout {
            s.entries[validCount] = entry
            validCount++
        }
    }

    s.entries = s.entries[:validCount]
}



type WorkerPool struct {
    workersNum int           // 工作goroutine数量
    jobChan    chan Job      // 作业队列
    // jobQueue   *ViolationIPQueue
    jobStack   *ViolationIPStack
    wg         sync.WaitGroup  // 等待组,用于确保所有作业完成
}

type Job struct {
    IP string
}

func NewWorkerPool(maxWorkers int) *WorkerPool {
    return &WorkerPool{
        workersNum: maxWorkers,
        jobChan:    make(chan Job, 1000), // 设置合理的缓冲区大小
        // jobQueue:   NewViolationIPQueue(violationIPTimeout),
        jobStack:   violationIPStack, // 使用全局的violationIPStack实例
    }
}

func (wp *WorkerPool) AddJobWithTimeout(ip string) {
    wp.jobStack.Push(ip)
}

func (wp *WorkerPool) Run() {
    for i := 0; i < wp.workersNum; i++ {
        wp.wg.Add(1)
        go wp.worker()
    }
    wp.wg.Wait()
    close(wp.jobChan)
}

func (wp *WorkerPool) worker() {
    defer wp.wg.Done()

    for {
	    // ip := wp.jobQueue.Dequeue()
	    ip := wp.jobStack.Pop()
	    if ip != "" {
	        findProcess(ip)
	    } 
    }

}


func init() {
	
	// fmt.Println("Timezone fix.")
	// fixTimeZone
	// China Time. Asia/Shanghai. GMT 8:00	
	time.Local = time.FixedZone("GMT", 8*3600) 

}


func main() {

	setUsage()

	start()

}

func start(){

	ctx, cancel := context.WithCancel(context.Background())
    defer cancel() // 确保在主goroutine退出时取消上下文

	var err error

	timeString := time.Now().Format("060102_150405")

	runtime.GOMAXPROCS(2)

	geoIP2CNReader, _ = newGeoIP2CNReader()


	// 初始化日志
	logFs, err := os.Create(outputDir+fmt.Sprintf("result_%v_%v.log", programName, timeString))
	if err != nil {
		log.Fatalf("Log file create: %v", err)
	}
	defer logFs.Close()

	// 设置日志输出到终端和文件
	log.SetOutput(io.MultiWriter(os.Stdout, logFs))

	// 提取网卡名
	interfaces := getInterfaces()

	violationIPStack = NewViolationIPStack(violationIPTimeout)

	workerPool = NewWorkerPool(maxGoroutineNum) // 设置合理的工作goroutine数量
    defer workerPool.Run()

    go workerPool.Run()

	for _, iface := range interfaces {
		
		go capture(iface, ctx)

	}


	// waitExit(ctx, cancel)
	waitExit()
}


// func waitExit(ctx context.Context, cancel context.CancelFunc){
func waitExit(){
	// 捕获 Ctrl+C 信号
	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	//等待信号
	<-c


	// fmt.Println("Start stopping violation detection...")
	if geoIP2CNReader != nil {
        geoIP2CNReader.reader.Close()
    }

    // cancel()

	fmt.Println()
	fmt.Println("Byebye...")
	os.Exit(0)

	// return
	
}


func setUsage() {

	var helpFlag bool
	// var backgroundFlag bool
	flag.BoolVar(&helpFlag, "h", false, "帮助信息. Show help information.")
	// flag.BoolVar(&backgroundFlag, "b", false, "后台运行. Run background.")
	//默认检测国内车型
	flag.BoolVar(&foreignFlag, "foreign", false, "切换为国外车型的跨境合规检测. Declare this is foreigen car.")
	flag.BoolVar(&savePcapFlag, "save", false, "使能本地保存Pcap流量包(存储空间消耗大).")
	flag.StringVar(&outputDir, "o", "", "指定日志、流量包的保存目录(默认为当前执行路径目录).")	
	flag.BoolVar(&findProcessFlag, "who", false, "使能查找违规IP通信的进程(性能消耗大).")
	flag.StringVar(&interfaceFlag, "i", "", "-i eth0,wlan0 指定网卡. Specify the network interface")

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
		fmt.Printf("%s-%s, databaseVersion:%s\n", programName, Version, databaseVersion)
		fmt.Println("默认检测国内车型IP合规. 可使用 -h 参数获取帮助详情.")
		fmt.Println("IP compliance detection of China models by default. ")
		fmt.Println("Please use the -h parameter to get more details.")
	} else{
		fmt.Println("脚本正在检测国外车型IP合规.")
		fmt.Println("Now checking IP compliance of foreign models.")
	}


	time.Sleep(2 * time.Second)

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

func capture(ifaceName string, ctx context.Context){
	fmt.Println("开启 " + ifaceName + " 网卡抓包。")

	// 打开网络设备
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		// 打开失败不退出程序
		fmt.Printf("OpenLive: %v\n",err)
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
			log.Fatalf("pcap, os.Create: %v", err)
		}

		pcapWriter = pcapgo.NewWriter(pcapFile)
		if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			log.Fatalf("pcapWriter.WriteFileHeader: %v", err)
		}

		defer pcapFile.Close()
	}

	// 设置过滤器
	err = handle.SetBPFFilter("ip and not ((dst net 192.168.0.0/16 or dst net 172.16.0.0/12 or dst net 10.0.0.0/8 or dst net 255.255.255.255 or dst net 169.254.0.0/16 or dst net 224.0.0.0/4 or dst net 127.0.0.0/8) and (src net 192.168.0.0/16 or src net 172.16.0.0/12 or src net 10.0.0.0/8 or src net 169.254.0.0/16 or src net 127.0.0.0/8))")
	if err != nil {
		log.Fatal("SetBPFFilter: %v",err)
	}

	// 开始抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
        
        case <-ctx.Done():
            // 上下文被取消,做一些清理工作并退出goroutine
            // cleanupCapture()
            return
        
        default:
            // 正常捕获数据包的循环
            if pcapWriter != nil {
			// 保存
				err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				if err != nil {
					log.Fatalf("pcap.WritePacket: %v", err)
				}
			}
			// print(1)

			go prasePacket(packet)
        }	
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

		if findProcessFlag {
			// 查找发起连接的进程
			// workerPool.AddJob(dstIP)
			workerPool.AddJobWithTimeout(dstIP)
			// findProcess(dstIP)	
		}
		
	}
}


type GeoIP2CNReader struct {
	reader	*geoip2.Reader
	countryMap sync.Map // 使用sync.Map代替ipCountryMap和mutex
	// lock	sync.Mutex
}

func newGeoIP2CNReader() (*GeoIP2CNReader, error){

	// 初始化IP MMDB数据库
	bytes, err := staticFiles.ReadFile("GeoIP2-CN-20240523.mmdb")
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
		countryMap: sync.Map{}, // 初始化sync.Map
	}, err
}

func (rd *GeoIP2CNReader) isChinaIP(ip string) bool {

	// 检查IP是否已经解析过
	if country, ok := rd.countryMap.Load(ip); ok {
		return country.(string) == "CN"
	}

	record, err := rd.reader.Country(net.ParseIP(ip))
	if err != nil {
		log.Println("rd.reader.Country: ", err)
	}
	
	// 存储IP和国家码
	// mutex.Lock()
	// ipCountryMap[ip] = record.Country.IsoCode
	// mutex.Unlock()
	rd.countryMap.Store(ip, record.Country.IsoCode)


	return record.Country.IsoCode == "CN"
}



//True合规，False违规
func checkViolationIP(ip string) bool {

	// 排除响应包或外部主动请求的包
	netIP := net.ParseIP(ip)
	if netIP.IsPrivate() || netIP.IsLoopback() || netIP.IsMulticast() || 
	netIP.IsLinkLocalUnicast() || netIP.IsUnspecified() || ip=="255.255.255.255" {
		// fmt.Printf("Skip Src IP: %s.\n", sip)
		// fmt.Printf("Skip localnetwork IP: %s\n", ip)
		return true
	}

	// 复用对象，减少资源消耗
	if geoIP2CNReader.isChinaIP(ip){
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


