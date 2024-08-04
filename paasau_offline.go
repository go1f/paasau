package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"embed"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
)

var (
	wg           sync.WaitGroup
	ipCountryMap = make(map[string]string)
	databaseVersion = "GeoIP2-CN-20240523"
	mutex        sync.Mutex
	//go:embed GeoIP2-CN-20240523.mmdb
	staticFiles embed.FS
)

func lookupCountry(ip net.IP, db *geoip2.Reader, pcapFile string) {
	defer wg.Done()

	// 检查IP是否已经解析过
	mutex.Lock()
	if _, ok := ipCountryMap[ip.String()]; ok {
		mutex.Unlock()		
		return
	}
	// if country, ok := ipCountryMap[ip.String()]; ok {
	// 	mutex.Unlock()
	// 	if country != "CN" {
	// 		fmt.Printf("%s is not China IP. More details: %s\n", ip, pcapFile)
	// 	}
	// 	return
	// }
	mutex.Unlock()

	// 过滤私有IP地址和保留地址
	if isPrivateOrReservedIP(ip) {
		return
	}

	// 使用GeoIP数据库查询IP位置
	record, err := db.Country(ip)
	if err != nil {
		log.Println(err)
		return
	}

	// 存储IP和国家码
	mutex.Lock()
	ipCountryMap[ip.String()] = record.Country.IsoCode
	mutex.Unlock()

	// 如果不是中国大陆IP，输出
	if record.Country.IsoCode != "CN" {
		// fmt.Printf("%s is not China IP.\n", ip)

		fmt.Println(ip.String())
		// fmt.Printf("%s is not China IP. More details: %s\n", ip, pcapFile)
	}
}

func isPrivateOrReservedIP(ip net.IP) bool {

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || 
	ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.String()=="255.255.255.255"{
		return true
	}

	return false
}

func getPcapFiles(folderPath string) []string {
	var files []string
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".pcap" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return files
}

func main() {

	fmt.Printf("IP compliance detection tool for China models. IP databaseVersion: %s.\n", databaseVersion)
	fmt.Println()
	time.Sleep(1 * time.Second)

	// 检查命令行参数
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run paasau_offline.go <pcap_folder_path>")
		os.Exit(1)
	}

	// 获取pcap文件夹路径和GeoIP数据库路径
	folderPath := os.Args[1]
	// databasePath := os.Args[2]

	// 打开GeoIP数据库
	// db, err := geoip2.Open(databasePath)
		// 初始化IP MMDB数据库
	bytes, err := staticFiles.ReadFile("GeoIP2-CN-20240523.mmdb")
	if err != nil {
		log.Fatal("Failed to read MMDB:", err)
	}
	db, err := geoip2.FromBytes(bytes) 
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 获取文件夹中所有pcap文件路径
	pcapFiles := getPcapFiles(folderPath)

	// 逐个处理每个pcap文件
	for _, pcapFile := range pcapFiles {
		// 打开pcap文件
		handle, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Println(err)
			continue
		}
		defer handle.Close()

		ipCountryMap = make(map[string]string)

		fmt.Printf("Handling %s:\n", pcapFile)

		// 解析每个数据包
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// 获取IP层
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip := ipLayer.(*layers.IPv4).NetworkFlow().Dst().Raw()

			wg.Add(1)
			go lookupCountry(ip, db, pcapFile)
		}

		wg.Wait()
		fmt.Println()
	}

}
