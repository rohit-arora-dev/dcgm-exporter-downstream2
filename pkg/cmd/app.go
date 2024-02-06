package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/NVIDIA/dcgm-exporter/pkg/dcgmexporter"
	"github.com/NVIDIA/go-dcgm/pkg/dcgm"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	FlexKey                = "f" // Monitor all GPUs if MIG is disabled or all GPU instances if MIG is enabled
	MajorKey               = "g" // Monitor top-level entities: GPUs or NvSwitches or CPUs
	MinorKey               = "i" // Monitor sub-level entities: GPU instances/NvLinks/CPUCores - GPUI cannot be specified if MIG is disabled
	undefinedConfigMapData = "none"
	deviceUsageTemplate    = `Specify which devices dcgm-exporter monitors.
	Possible values: {{.FlexKey}} or 
	                 {{.MajorKey}}[:id1[,-id2...] or 
	                 {{.MinorKey}}[:id1[,-id2...].
	If an id list is used, then devices with match IDs must exist on the system. For example:
		(default) = monitor all GPU instances in MIG mode, all GPUs if MIG mode is disabled. (See {{.FlexKey}})
		{{.MajorKey}} = Monitor all GPUs
		{{.MinorKey}} = Monitor all GPU instances
		{{.FlexKey}} = Monitor all GPUs if MIG is disabled, or all GPU instances if MIG is enabled.
                       Note: this rule will be applied to each GPU. If it has GPU instances, those
                             will be monitored. If it doesn't, then the GPU will be monitored.
                             This is our recommended option for single or mixed MIG Strategies.
		{{.MajorKey}}:0,1 = monitor GPUs 0 and 1
		{{.MinorKey}}:0,2-4 = monitor GPU instances 0, 2, 3, and 4.

	NOTE 1: -i cannot be specified unless MIG mode is enabled.
	NOTE 2: Any time indices are specified, those indices must exist on the system.
	NOTE 3: In MIG mode, only -f or -i with a range can be specified. GPUs are not assigned to pods
		and therefore reporting must occur at the GPU instance level.`
)

const (
	CLIFieldsFile               = "collectors"
	CLIAddress                  = "address"
	CLICollectInterval          = "collect-interval"
	CLIKubernetes               = "kubernetes"
	CLIKubernetesGPUIDType      = "kubernetes-gpu-id-type"
	CLIUseOldNamespace          = "use-old-namespace"
	CLIRemoteHEInfo             = "remote-hostengine-info"
	CLIGPUDevices               = "devices"
	CLISwitchDevices            = "switch-devices"
	CLICPUDevices               = "cpu-devices"
	CLINoHostname               = "no-hostname"
	CLIUseFakeGPUs              = "fake-gpus"
	CLIConfigMapData            = "configmap-data"
	CLIWebSystemdSocket         = "web-systemd-socket"
	CLIWebConfigFile            = "web-config-file"
	CLIXIDCountWindowSize       = "xid-count-window-size"
	CLIReplaceBlanksInModelName = "replace-blanks-in-model-name"
	CLIEnableDCGMLog            = "enable-dcgm-log"
	CLIDCGMLogLevel             = "dcgm-log-level"
)

func NewApp(buildVersion ...string) *cli.App {
	c := cli.NewApp()
	c.Name = "DCGM Exporter"
	c.Usage = "Generates GPU metrics in the prometheus format"
	if len(buildVersion) == 0 {
		buildVersion = append(buildVersion, "")
	}
	c.Version = buildVersion[0]

	var deviceUsageBuffer bytes.Buffer
	t := template.Must(template.New("").Parse(deviceUsageTemplate))
	_ = t.Execute(&deviceUsageBuffer, map[string]string{"FlexKey": FlexKey, "MajorKey": MajorKey, "MinorKey": MinorKey})
	DeviceUsageStr := deviceUsageBuffer.String()

	c.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    CLIFieldsFile,
			Aliases: []string{"f"},
			Usage:   "Path to the file, that contains the DCGM fields to collect",
			Value:   "/etc/dcgm-exporter/default-counters.csv",
			EnvVars: []string{"DCGM_EXPORTER_COLLECTORS"},
		},
		&cli.StringFlag{
			Name:    CLIAddress,
			Aliases: []string{"a"},
			Value:   ":9400",
			Usage:   "Address",
			EnvVars: []string{"DCGM_EXPORTER_LISTEN"},
		},
		&cli.IntFlag{
			Name:    CLICollectInterval,
			Aliases: []string{"c"},
			Value:   30000,
			Usage:   "Interval of time at which point metrics are collected. Unit is milliseconds (ms).",
			EnvVars: []string{"DCGM_EXPORTER_INTERVAL"},
		},
		&cli.BoolFlag{
			Name:    CLIKubernetes,
			Aliases: []string{"k"},
			Value:   false,
			Usage:   "Enable kubernetes mapping metrics to kubernetes pods",
			EnvVars: []string{"DCGM_EXPORTER_KUBERNETES"},
		},
		&cli.BoolFlag{
			Name:    CLIUseOldNamespace,
			Aliases: []string{"o"},
			Value:   false,
			Usage:   "Use old 1.x namespace",
			EnvVars: []string{"DCGM_EXPORTER_USE_OLD_NAMESPACE"},
		},
		&cli.StringFlag{
			Name:    CLICPUDevices,
			Aliases: []string{"p"},
			Value:   FlexKey,
			Usage:   DeviceUsageStr,
			EnvVars: []string{"DCGM_EXPORTER_CPU_DEVICES_STR"},
		},
		&cli.StringFlag{
			Name:    CLIConfigMapData,
			Aliases: []string{"m"},
			Value:   undefinedConfigMapData,
			Usage:   "ConfigMap <NAMESPACE>:<NAME> for metric data",
			EnvVars: []string{"DCGM_EXPORTER_CONFIGMAP_DATA"},
		},
		&cli.StringFlag{
			Name:    CLIRemoteHEInfo,
			Aliases: []string{"r"},
			Value:   "localhost:5555",
			Usage:   "Connect to remote hostengine at <HOST>:<PORT>",
			EnvVars: []string{"DCGM_REMOTE_HOSTENGINE_INFO"},
		},
		&cli.StringFlag{
			Name:  CLIKubernetesGPUIDType,
			Value: string(dcgmexporter.GPUUID),
			Usage: fmt.Sprintf("Choose Type of GPU ID to use to map kubernetes resources to pods. Possible values: '%s', '%s'",
				dcgmexporter.GPUUID, dcgmexporter.DeviceName),
			EnvVars: []string{"DCGM_EXPORTER_KUBERNETES_GPU_ID_TYPE"},
		},
		&cli.StringFlag{
			Name:    CLIGPUDevices,
			Aliases: []string{"d"},
			Value:   FlexKey,
			Usage:   DeviceUsageStr,
			EnvVars: []string{"DCGM_EXPORTER_DEVICES_STR"},
		},
		&cli.BoolFlag{
			Name:    CLINoHostname,
			Aliases: []string{"n"},
			Value:   false,
			Usage:   "Omit the hostname information from the output, matching older versions.",
			EnvVars: []string{"DCGM_EXPORTER_NO_HOSTNAME"},
		},
		&cli.StringFlag{
			Name:    CLISwitchDevices,
			Aliases: []string{"s"},
			Value:   FlexKey,
			Usage:   DeviceUsageStr,
			EnvVars: []string{"DCGM_EXPORTER_OTHER_DEVICES_STR"},
		},
		&cli.BoolFlag{
			Name:    CLIUseFakeGPUs,
			Value:   false,
			Usage:   "Accept GPUs that are fake, for testing purposes only",
			EnvVars: []string{"DCGM_EXPORTER_USE_FAKE_GPUS"},
		},
		&cli.StringFlag{
			Name:    CLIWebConfigFile,
			Value:   "",
			Usage:   "TLS config file following webConfig spec.",
			EnvVars: []string{"DCGM_EXPORTER_WEB_CONFIG_FILE"},
		},
		&cli.IntFlag{
			Name:    CLIXIDCountWindowSize,
			Aliases: []string{"x"},
			Value:   int((5 * time.Minute).Milliseconds()),
			Usage:   "Set time window size in milliseconds (ms) for counting active XID errors in DCGM Exporter.",
			EnvVars: []string{"DCGM_EXPORTER_XID_COUNT_WINDOW_SIZE"},
		},
		&cli.BoolFlag{
			Name:    CLIReplaceBlanksInModelName,
			Aliases: []string{"rbmn"},
			Value:   false,
			Usage:   "Replace every blank space in the GPU model name with a dash, ensuring a continuous, space-free identifier.",
			EnvVars: []string{"DCGM_EXPORTER_REPLACE_BLANKS_IN_MODEL_NAME"},
		},
		&cli.BoolFlag{
			Name:    CLIEnableDCGMLog,
			Value:   false,
			Usage:   "Enable writing DCGM logs to standard output (stdout).",
			EnvVars: []string{"DCGM_EXPORTER_ENABLE_DCGM_LOG"},
		},
		&cli.StringFlag{
			Name:    CLIDCGMLogLevel,
			Value:   dcgmexporter.DCGMDbgLvlNone,
			Usage:   "Specify the DCGM log verbosity level. This parameter is effective only when the '--enable-dcgm-log' option is set to 'true'. Possible values: NONE, FATAL, ERROR, WARN, INFO, DEBUG and VERB",
			EnvVars: []string{"DCGM_EXPORTER_DCGM_LOG_LEVEL"},
		},
	}

	if runtime.GOOS == "linux" {
		c.Flags = append(c.Flags, &cli.BoolFlag{
			Name:    CLIWebSystemdSocket,
			Value:   false,
			Usage:   "Use systemd socket activation listeners instead of port listeners (Linux only).",
			EnvVars: []string{"DCGM_EXPORTER_SYSTEMD_SOCKET"},
		})
	} else {
		err := "dcgm-exporter is only supported on Linux."
		logrus.Fatal(err)
		return nil
	}

	c.Action = func(c *cli.Context) error {
		return action(c)
	}

	return c
}

func newOSWatcher(sigs ...os.Signal) chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, sigs...)

	return sigChan
}

func action(c *cli.Context) error {
restart:
	// Clone Stdout to origStdout.
	origStdout, err := syscall.Dup(syscall.Stdout)
	if err != nil {
		log.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		log.Fatal(err)
	}

	// Clone the pipe's writer to the actual Stdout descriptor; from this point
	// on, writes to Stdout will go to w.
	if err = syscall.Dup2(int(w.Fd()), syscall.Stdout); err != nil {
		log.Fatal(err)
	}

	// Write log entries to the original stdout
	devTTY := os.NewFile(uintptr(origStdout), "/dev/tty")
	logrus.SetOutput(devTTY)

	go func() {
		devTTY := os.NewFile(uintptr(origStdout), "/dev/tty")
		logger := logrus.New()
		logger.Out = devTTY
		logger.Level = logrus.GetLevel()
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			logEntry := scanner.Text()
			parsedLogEntry, err := parseLogEntry(logEntry)
			if err != nil {
				log.Fatalf("Failed to parse log entry: %v", err)
			}
			entry := logrus.NewEntry(logger)
			entry.WithField("dcgm_level", parsedLogEntry.Level).Info(parsedLogEntry.Message)
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading from pipe: %v", err)
		}
	}()

	defer func() {
		w.Close()
		syscall.Close(syscall.Stdout)
		// Restore original Stdout.
		syscall.Dup2(origStdout, syscall.Stdout)
		syscall.Close(origStdout)
	}()

	logrus.Info("Starting dcgm-exporter")
	config, err := contextToConfig(c)
	if err != nil {
		return err
	}

	if config.UseRemoteHE {
		logrus.Info("Attemping to connect to remote hostengine at ", config.RemoteHEInfo)
		cleanup, err := dcgm.Init(dcgm.Standalone, config.RemoteHEInfo, "0")
		defer cleanup()
		if err != nil {
			logrus.Fatal(err)
		}
	} else {

		if config.EnableDCGMLog {
			os.Setenv("__DCGM_DBG_FILE", "-")
			os.Setenv("__DCGM_DBG_LVL", config.DCGMLogLevel)
		}

		cleanup, err := dcgm.Init(dcgm.Embedded)
		defer cleanup()
		if err != nil {
			logrus.Fatal(err)
		}
	}
	logrus.Info("DCGM successfully initialized!")

	dcgm.FieldsInit()
	defer dcgm.FieldsTerm()

	var groups []dcgm.MetricGroup
	groups, err = dcgm.GetSupportedMetricGroups(0)
	if err != nil {
		config.CollectDCP = false
		logrus.Info("Not collecting DCP metrics: ", err)
	} else {
		logrus.Info("Collecting DCP Metrics")
		config.MetricGroups = groups
	}

	counters, exporterCounters, err := dcgmexporter.ExtractCounters(config)
	if err != nil {
		logrus.Fatal(err)
	}

	// Copy labels from counters to exporterCounters
	for i := range counters {
		if counters[i].PromType == "label" {
			exporterCounters = append(exporterCounters, counters[i])
		}
	}

	hostname, err := dcgmexporter.GetHostname(config)
	if err != nil {
		return err
	}

	ch := make(chan string, 10)

	pipeline, cleanup, err := dcgmexporter.NewMetricsPipeline(config, counters, hostname, dcgmexporter.NewDCGMCollector)
	defer cleanup()
	if err != nil {
		logrus.Fatal(err)
	}

	cRegistry := dcgmexporter.NewRegistry()

	if dcgmexporter.IsdcgmExpXIDErrorsCountEnabled(exporterCounters) {
		xidCollector, err := dcgmexporter.NewXIDCollector(config, exporterCounters, hostname)
		if err != nil {
			logrus.Fatal(err)
		}

		defer func() {
			xidCollector.Cleanup()
		}()

		cRegistry.Register(xidCollector)
	}

	server, cleanup, err := dcgmexporter.NewMetricsServer(config, ch, cRegistry)
	defer cleanup()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	stop := make(chan interface{})

	wg.Add(1)
	go pipeline.Run(ch, stop, &wg)

	wg.Add(1)
	go server.Run(stop, &wg)

	sigs := newOSWatcher(syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	sig := <-sigs
	close(stop)
	err = dcgmexporter.WaitWithTimeout(&wg, time.Second*2)
	if err != nil {
		logrus.Fatal(err)
	}

	if sig == syscall.SIGHUP {
		goto restart
	}

	return nil
}

func parseDeviceOptions(devices string) (dcgmexporter.DeviceOptions, error) {
	var dOpt dcgmexporter.DeviceOptions

	letterAndRange := strings.Split(devices, ":")
	count := len(letterAndRange)
	if count > 2 {
		return dOpt, fmt.Errorf("Invalid ranged device option '%s': there can only be one specified range", devices)
	}

	letter := letterAndRange[0]
	if letter == FlexKey {
		dOpt.Flex = true
		if count > 1 {
			return dOpt, fmt.Errorf("No range can be specified with the flex option 'f'")
		}
	} else if letter == MajorKey || letter == MinorKey {
		var indices []int
		if count == 1 {
			// No range means all present devices of the type
			indices = append(indices, -1)
		} else {
			numbers := strings.Split(letterAndRange[1], ",")
			for _, numberOrRange := range numbers {
				rangeTokens := strings.Split(numberOrRange, "-")
				rangeTokenCount := len(rangeTokens)
				if rangeTokenCount > 2 {
					return dOpt, fmt.Errorf("A range can only be '<number>-<number>', but found '%s'", numberOrRange)
				} else if rangeTokenCount == 1 {
					number, err := strconv.Atoi(rangeTokens[0])
					if err != nil {
						return dOpt, err
					}
					indices = append(indices, number)
				} else {
					start, err := strconv.Atoi(rangeTokens[0])
					if err != nil {
						return dOpt, err
					}
					end, err := strconv.Atoi(rangeTokens[1])
					if err != nil {
						return dOpt, err
					}

					// Add the range to the indices
					for i := start; i <= end; i++ {
						indices = append(indices, i)
					}
				}
			}
		}

		if letter == MajorKey {
			dOpt.MajorRange = indices
		} else {
			dOpt.MinorRange = indices
		}
	} else {
		return dOpt, fmt.Errorf("The only valid options preceding ':<range>' are 'g' or 'i', but found '%s'", letter)
	}

	return dOpt, nil
}

func contextToConfig(c *cli.Context) (*dcgmexporter.Config, error) {
	gOpt, err := parseDeviceOptions(c.String(CLIGPUDevices))
	if err != nil {
		return nil, err
	}

	sOpt, err := parseDeviceOptions(c.String(CLISwitchDevices))
	if err != nil {
		return nil, err
	}

	cOpt, err := parseDeviceOptions(c.String(CLICPUDevices))
	if err != nil {
		return nil, err
	}

	dcgmLogLevel := c.String(CLIDCGMLogLevel)
	if !slices.Contains(dcgmexporter.DCGMDbgLvlValues, dcgmLogLevel) {
		return nil, fmt.Errorf("Invalid %s parameter value: %s", CLIDCGMLogLevel, dcgmLogLevel)
	}

	return &dcgmexporter.Config{
		CollectorsFile:           c.String(CLIFieldsFile),
		Address:                  c.String(CLIAddress),
		CollectInterval:          c.Int(CLICollectInterval),
		Kubernetes:               c.Bool(CLIKubernetes),
		KubernetesGPUIdType:      dcgmexporter.KubernetesGPUIDType(c.String(CLIKubernetesGPUIDType)),
		CollectDCP:               true,
		UseOldNamespace:          c.Bool(CLIUseOldNamespace),
		UseRemoteHE:              c.IsSet(CLIRemoteHEInfo),
		RemoteHEInfo:             c.String(CLIRemoteHEInfo),
		GPUDevices:               gOpt,
		SwitchDevices:            sOpt,
		CPUDevices:               cOpt,
		NoHostname:               c.Bool(CLINoHostname),
		UseFakeGPUs:              c.Bool(CLIUseFakeGPUs),
		ConfigMapData:            c.String(CLIConfigMapData),
		WebSystemdSocket:         c.Bool(CLIWebSystemdSocket),
		WebConfigFile:            c.String(CLIWebConfigFile),
		XIDCountWindowSize:       c.Int(CLIXIDCountWindowSize),
		ReplaceBlanksInModelName: c.Bool(CLIReplaceBlanksInModelName),
		EnableDCGMLog:            c.Bool(CLIEnableDCGMLog),
		DCGMLogLevel:             dcgmLogLevel,
	}, nil
}

// LogEntry represents the structured form of the parsed log entry.
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
}

// parseLogEntry takes a log entry string and returns a structured LogEntry object.
func parseLogEntry(entry string) (*LogEntry, error) {
	// Split the entry by spaces, taking care to not split the function call and its arguments.
	fields := strings.Fields(entry)

	// Parse the timestamp.
	timestamp, err := time.Parse("2006-01-02 15:04:05.000", fields[0]+" "+fields[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %v", err)
	}

	level := fields[2]

	// Reconstruct the string from the fourth field onwards to deal with function calls and arguments.
	remainder := strings.Join(fields[4:], " ")

	return &LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Message:   remainder,
	}, nil
}
