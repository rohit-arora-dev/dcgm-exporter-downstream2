package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/NVIDIA/go-dcgm/pkg/dcgm"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/NVIDIA/dcgm-exporter/pkg/dcgmexporter"
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
	CLIFieldsFile                 = "collectors"
	CLIAddress                    = "address"
	CLICollectInterval            = "collect-interval"
	CLIKubernetes                 = "kubernetes"
	CLIKubernetesGPUIDType        = "kubernetes-gpu-id-type"
	CLIUseOldNamespace            = "use-old-namespace"
	CLIRemoteHEInfo               = "remote-hostengine-info"
	CLIGPUDevices                 = "devices"
	CLISwitchDevices              = "switch-devices"
	CLICPUDevices                 = "cpu-devices"
	CLINoHostname                 = "no-hostname"
	CLIUseFakeGPUs                = "fake-gpus"
	CLIConfigMapData              = "configmap-data"
	CLIWebSystemdSocket           = "web-systemd-socket"
	CLIWebConfigFile              = "web-config-file"
	CLIXIDCountWindowSize         = "xid-count-window-size"
	CLIReplaceBlanksInModelName   = "replace-blanks-in-model-name"
	CLIDebugMode                  = "debug"
	CLIClockEventsCountWindowSize = "clock-events-count-window-size"
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
			Usage:   "Replaces every blank space in the GPU model name with a dash, ensuring a continuous, space-free identifier.",
			EnvVars: []string{"DCGM_EXPORTER_REPLACE_BLANKS_IN_MODEL_NAME"},
		},
		&cli.BoolFlag{
			Name:    CLIDebugMode,
			Value:   false,
			Usage:   "Enable debug output",
			EnvVars: []string{"DCGM_EXPORTER_DEBUG"},
		},
		&cli.IntFlag{
			Name:    CLIClockEventsCountWindowSize,
			Value:   int((5 * time.Minute).Milliseconds()),
			Usage:   "Set time window size in milliseconds (ms) for counting clock events in DCGM Exporter.",
			EnvVars: []string{"DCGM_EXPORTER_CLOCK_EVENTS_COUNT_WINDOW_SIZE"},
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

func action(c *cli.Context) (err error) {
restart:

	// The purpose of this function is to capture any panic that may occur
	// during initialization and return an error.
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField(dcgmexporter.LoggerStackTrace, string(debug.Stack())).Error("Encountered a failure.")
			err = fmt.Errorf("encountered a failure; err: %v", r)
		}
	}()

	logrus.Info("Starting dcgm-exporter")
	config, err := contextToConfig(c)
	if err != nil {
		return err
	}

	if config.Debug {
		// enable debug logging
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Debug output is enabled")
	}

	logrus.Debugf("Command line: %s", strings.Join(os.Args, " "))

	logrus.WithField(dcgmexporter.LoggerDumpKey, fmt.Sprintf("%+v", config)).Debug("Loaded configuration")

	if config.UseRemoteHE {
		logrus.Info("Attemping to connect to remote hostengine at ", config.RemoteHEInfo)
		cleanup, err := dcgm.Init(dcgm.Standalone, config.RemoteHEInfo, "0")
		defer cleanup()
		if err != nil {
			logrus.Fatal(err)
		}
	} else {
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

	cs, err := dcgmexporter.GetCounterSet(config)

	if err != nil {
		logrus.Fatal(err)
	}

	// Copy labels from DCGM Counters to ExporterCounters
	for i := range cs.DCGMCounters {
		if cs.DCGMCounters[i].PromType == "label" {
			cs.ExporterCounters = append(cs.ExporterCounters, cs.DCGMCounters[i])
		}
	}

	hostname, err := dcgmexporter.GetHostname(config)
	if err != nil {
		return err
	}

	allCounters := []dcgmexporter.Counter{}

	allCounters = append(allCounters, cs.DCGMCounters...)
	allCounters = append(allCounters,
		dcgmexporter.Counter{
			FieldID: dcgm.DCGM_FI_DEV_CLOCK_THROTTLE_REASONS,
		},
		dcgmexporter.Counter{
			FieldID: dcgm.DCGM_FI_DEV_XID_ERRORS,
		},
	)

	fieldEntityGroupTypeSystemInfo := dcgmexporter.NewEntityGroupTypeSystemInfo(allCounters, config)

	for _, egt := range dcgmexporter.FieldEntityGroupTypeToMonitor {
		err := fieldEntityGroupTypeSystemInfo.Load(egt)
		if err != nil {
			logrus.Infof("Not collecting %s metrics; %s", egt.String(), err)
		}
	}

	ch := make(chan string, 10)

	pipeline, cleanup, err := dcgmexporter.NewMetricsPipeline(config,
		cs.DCGMCounters,
		hostname,
		dcgmexporter.NewDCGMCollector,
		fieldEntityGroupTypeSystemInfo,
	)
	defer cleanup()
	if err != nil {
		logrus.Fatal(err)
	}

	cRegistry := dcgmexporter.NewRegistry()

	if dcgmexporter.IsDCGMExpXIDErrorsCountEnabled(cs.ExporterCounters) {
		item, exists := fieldEntityGroupTypeSystemInfo.Get(dcgm.FE_GPU)
		if !exists {
			logrus.Fatalf("%s collector cannot be initialized", dcgmexporter.DCGMXIDErrorsCount.String())
		}

		xidCollector, err := dcgmexporter.NewXIDCollector(cs.ExporterCounters, hostname, config, item)
		if err != nil {
			logrus.Fatal(err)
		}

		cRegistry.Register(xidCollector)

		logrus.Infof("%s collector initialized", dcgmexporter.DCGMXIDErrorsCount.String())
	}

	if dcgmexporter.IsDCGMExpClockEventsCountEnabled(cs.ExporterCounters) {
		item, exists := fieldEntityGroupTypeSystemInfo.Get(dcgm.FE_GPU)
		if !exists {
			logrus.Fatalf("%s collector cannot be initialized", dcgmexporter.DCGMClockEventsCount.String())
		}
		clocksThrottleReasonsCollector, err := dcgmexporter.NewClockEventsCollector(
			cs.ExporterCounters, hostname, config, item)
		if err != nil {
			logrus.Fatal(err)
		}

		cRegistry.Register(clocksThrottleReasonsCollector)

		logrus.Infof("%s collector initialized", dcgmexporter.DCGMClockEventsCount.String())
	}

	defer func() {
		cRegistry.Cleanup()
	}()

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
		return dOpt, fmt.Errorf("invalid ranged device option '%s'; err: there can only be one specified range",
			devices)
	}

	letter := letterAndRange[0]
	if letter == FlexKey {
		dOpt.Flex = true
		if count > 1 {
			return dOpt, fmt.Errorf("no range can be specified with the flex option 'f'")
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
					return dOpt, fmt.Errorf("range can only be '<number>-<number>', but found '%s'", numberOrRange)
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
		return dOpt, fmt.Errorf("valid options preceding ':<range>' are 'g' or 'i', but found '%s'", letter)
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

	return &dcgmexporter.Config{
		CollectorsFile:             c.String(CLIFieldsFile),
		Address:                    c.String(CLIAddress),
		CollectInterval:            c.Int(CLICollectInterval),
		Kubernetes:                 c.Bool(CLIKubernetes),
		KubernetesGPUIdType:        dcgmexporter.KubernetesGPUIDType(c.String(CLIKubernetesGPUIDType)),
		CollectDCP:                 true,
		UseOldNamespace:            c.Bool(CLIUseOldNamespace),
		UseRemoteHE:                c.IsSet(CLIRemoteHEInfo),
		RemoteHEInfo:               c.String(CLIRemoteHEInfo),
		GPUDevices:                 gOpt,
		SwitchDevices:              sOpt,
		CPUDevices:                 cOpt,
		NoHostname:                 c.Bool(CLINoHostname),
		UseFakeGPUs:                c.Bool(CLIUseFakeGPUs),
		ConfigMapData:              c.String(CLIConfigMapData),
		WebSystemdSocket:           c.Bool(CLIWebSystemdSocket),
		WebConfigFile:              c.String(CLIWebConfigFile),
		XIDCountWindowSize:         c.Int(CLIXIDCountWindowSize),
		ReplaceBlanksInModelName:   c.Bool(CLIReplaceBlanksInModelName),
		Debug:                      c.Bool(CLIDebugMode),
		ClockEventsCountWindowSize: c.Int(CLIClockEventsCountWindowSize),
	}, nil
}
