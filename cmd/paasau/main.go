package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"paasau/internal/config"
	"paasau/internal/live"
	"paasau/internal/offline"
)

const defaultConfigPath = "configs/default.json"

func main() {
	if len(os.Args) < 2 {
		if !liveSupported() {
			printRootUsage()
			return
		}
		runLive(nil)
		return
	}

	switch os.Args[1] {
	case "live":
		runLive(os.Args[2:])
	case "offline":
		runOffline(os.Args[2:])
	case "-h", "--help", "help":
		printRootUsage()
	case "":
		if !liveSupported() {
			printRootUsage()
			return
		}
		runLive(nil)
	default:
		if strings.HasPrefix(os.Args[1], "-") {
			if !liveSupported() {
				fmt.Fprintln(os.Stderr, "live capture is not supported in Windows builds; use the offline subcommand instead")
				printRootUsage()
				os.Exit(2)
			}
			runLive(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printRootUsage()
		os.Exit(2)
	}
}

func runLive(args []string) {
	fs := flag.NewFlagSet("live", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Path to config file")
	policyName := fs.String("policy", "", "Policy name from config")
	foreign := fs.Bool("foreign", false, "Switch to foreign-car policy for compatibility")
	interfacesFlag := fs.String("i", "", "Comma-separated interfaces")
	outputDir := fs.String("o", "", "Output directory for logs and captures")
	geoIPDB := fs.String("db", "", "GeoIP MMDB file path")
	bpfFilter := fs.String("filter", "", "BPF filter override")
	savePcap := fs.Bool("save", false, "Save captured packets")
	findProcess := fs.Bool("who", false, "Find process for violated connections")
	processName := fs.String("pn", "", "Only search matched process names (regexp)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), liveUsageString(os.Args[0]))
	}
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		exitErr(err)
	}
	applyTimeZone(cfg.Runtime.TimeZone)
	*policyName = resolvePolicyName(*policyName, *foreign)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := live.Options{
		PolicyName:  *policyName,
		Interfaces:  splitCSV(*interfacesFlag),
		OutputDir:   *outputDir,
		GeoIPDB:     *geoIPDB,
		BPFFilter:   *bpfFilter,
		SavePcap:    *savePcap,
		FindProcess: *findProcess,
		ProcessName: *processName,
	}
	if err := live.Run(ctx, cfg, opts); err != nil {
		exitErr(err)
	}
}

func runOffline(args []string) {
	fs := flag.NewFlagSet("offline", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Path to config file")
	policyName := fs.String("policy", "", "Policy name from config")
	foreign := fs.Bool("foreign", false, "Switch to foreign-car policy for compatibility")
	geoIPDB := fs.String("db", "", "GeoIP MMDB file path")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), offlineUsageString(os.Args[0]))
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		exitErr(err)
	}
	applyTimeZone(cfg.Runtime.TimeZone)
	*policyName = resolvePolicyName(*policyName, *foreign)

	opts := offline.Options{
		PolicyName: *policyName,
		GeoIPDB:    *geoIPDB,
		InputDir:   fs.Arg(0),
	}
	if err := offline.Run(cfg, opts); err != nil {
		exitErr(err)
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func applyTimeZone(name string) {
	if strings.TrimSpace(name) == "" {
		return
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load timezone %q: %v\n", name, err)
		return
	}
	time.Local = loc
}

func printRootUsage() {
	fmt.Print(rootUsageString(os.Args[0]))
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func rootUsageString(program string) string {
	return rootUsageStringForMode(program, liveSupported())
}

func rootUsageStringForMode(program string, liveAvailable bool) string {
	var b strings.Builder
	b.WriteString("Usage: ")
	b.WriteString(program)
	b.WriteString(" <subcommand> [flags]\n\n")
	b.WriteString("Default behavior: ")
	b.WriteString(program)
	if liveAvailable {
		b.WriteString(" [live flags]\n\n")
	} else {
		b.WriteString(" offline <pcap-dir>\n\n")
	}
	b.WriteString("Subcommands:\n")
	if liveAvailable {
		b.WriteString("  live      Capture live traffic and detect policy violations (default)\n")
	} else {
		b.WriteString("  live      Not supported in Windows builds\n")
	}
	b.WriteString("  offline   Scan pcap files in a directory\n\n")
	b.WriteString("Config default: ")
	b.WriteString(defaultConfigPath)
	b.WriteString("\n\n")
	if liveAvailable {
		b.WriteString("Live flags:\n")
		b.WriteString("  -config <file>   Config file path\n")
		b.WriteString("  -policy <name>   Policy name, e.g. china-car / foreign-car\n")
		b.WriteString("  -i <if0,if1>     Capture interfaces\n")
		b.WriteString("  -o <dir>         Output directory\n")
		b.WriteString("  -db <file>       GeoIP MMDB path\n")
		b.WriteString("  -filter <expr>   BPF filter override\n")
		b.WriteString("  -save            Save captured packets\n")
		b.WriteString("  -who             Find process for violated connections\n")
		b.WriteString("  -pn <regex>      Limit process lookup by process name\n\n")
	} else {
		b.WriteString("Windows note:\n")
		b.WriteString("  This build only supports offline scanning.\n\n")
	}
	b.WriteString("Offline flags:\n")
	b.WriteString("  -config <file>   Config file path\n")
	b.WriteString("  -policy <name>   Policy name\n")
	b.WriteString("  -db <file>       GeoIP MMDB path\n\n")
	b.WriteString("Detailed help:\n")
	if liveAvailable {
		b.WriteString("  ")
		b.WriteString(program)
		b.WriteString(" live -h\n")
	}
	b.WriteString("  ")
	b.WriteString(program)
	b.WriteString(" offline -h\n\n")
	b.WriteString("Examples:\n")
	if liveAvailable {
		b.WriteString("  ")
		b.WriteString(program)
		b.WriteString(" -who -save\n")
	}
	b.WriteString("  ")
	b.WriteString(program)
	b.WriteString(" offline ./pcap_dump\n")
	return b.String()
}

func liveUsageString(program string) string {
	return commandUsageString(program, "live", "[flags]", []flagLine{
		{name: "-config", arg: "<file>", desc: "Path to config file"},
		{name: "-policy", arg: "<name>", desc: "Policy name from config"},
		{name: "-foreign", desc: "Compatibility alias for -policy foreign-car"},
		{name: "-i", arg: "<if0,if1>", desc: "Comma-separated interfaces"},
		{name: "-o", arg: "<dir>", desc: "Output directory for logs and captures"},
		{name: "-db", arg: "<file>", desc: "GeoIP MMDB file path"},
		{name: "-filter", arg: "<expr>", desc: "BPF filter override"},
		{name: "-save", desc: "Save captured packets"},
		{name: "-who", desc: "Find process for violated connections"},
		{name: "-pn", arg: "<regex>", desc: "Only search matched process names (regexp)"},
	})
}

func offlineUsageString(program string) string {
	return commandUsageString(program, "offline", "[flags] <pcap-dir>", []flagLine{
		{name: "-config", arg: "<file>", desc: "Path to config file"},
		{name: "-policy", arg: "<name>", desc: "Policy name from config"},
		{name: "-foreign", desc: "Compatibility alias for -policy foreign-car"},
		{name: "-db", arg: "<file>", desc: "GeoIP MMDB file path"},
	})
}

type flagLine struct {
	name string
	arg  string
	desc string
}

func commandUsageString(program string, subcommand string, suffix string, lines []flagLine) string {
	var b strings.Builder
	b.WriteString("Usage: ")
	b.WriteString(program)
	b.WriteString(" ")
	b.WriteString(subcommand)
	if suffix != "" {
		b.WriteString(" ")
		b.WriteString(suffix)
	}
	b.WriteString("\n\n")

	width := 0
	rendered := make([]string, len(lines))
	for i, line := range lines {
		rendered[i] = line.name
		if line.arg != "" {
			rendered[i] += " " + line.arg
		}
		if len(rendered[i]) > width {
			width = len(rendered[i])
		}
	}

	b.WriteString("Flags:\n")
	for i, line := range lines {
		b.WriteString("  ")
		b.WriteString(rendered[i])
		b.WriteString(strings.Repeat(" ", width-len(rendered[i])+3))
		b.WriteString(line.desc)
		b.WriteString("\n")
	}

	b.WriteString("\nExamples:\n")
	if subcommand == "live" {
		b.WriteString("  ")
		b.WriteString(program)
		b.WriteString(" -i wlan0 -who\n")
		b.WriteString("  ")
		b.WriteString(program)
		b.WriteString(" live -save -filter ")
		b.WriteString(strconv.Quote("tcp or udp"))
		b.WriteString("\n")
	} else {
		b.WriteString("  ")
		b.WriteString(program)
		b.WriteString(" offline ./pcap_dump\n")
	}
	return b.String()
}

func liveSupported() bool {
	return runtime.GOOS != "windows"
}

func resolvePolicyName(policyName string, foreign bool) string {
	if foreign && strings.TrimSpace(policyName) == "" {
		return "foreign-car"
	}
	return policyName
}
