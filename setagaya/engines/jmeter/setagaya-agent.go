package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	etree "github.com/beevik/etree"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "go.uber.org/automaxprocs"

	"github.com/hveda/Setagaya/setagaya/config"
	sos "github.com/hveda/Setagaya/setagaya/object_storage"

	"github.com/hveda/Setagaya/setagaya/engines/containerstats"
	enginesModel "github.com/hveda/Setagaya/setagaya/engines/model"
	"github.com/hveda/Setagaya/setagaya/model"
	"github.com/hveda/Setagaya/setagaya/utils"

	"github.com/hpcloud/tail"
)

// validateJMeterPath ensures the JMeter path is safe and within expected boundaries
func validateJMeterPath(path string) bool {
	// Define allowed JMeter paths (container-safe)
	allowedPaths := []string{
		"/apache-jmeter-3.3/bin",       // Legacy JMeter 3.3
		"/opt/apache-jmeter-5.6.3/bin", // Modern JMeter 5.6.3
	}

	// Check if path matches any allowed pattern
	for _, allowedPath := range allowedPaths {
		if path == allowedPath {
			return true
		}
	}

	// Allow paths that match the pattern /opt/apache-jmeter-X.X.X/bin
	matched, err := regexp.MatchString(`^/opt/apache-jmeter-\d+\.\d+\.\d+/bin$`, path)
	if err != nil {
		log.Printf("Error matching regex pattern: %v", err)
		return false
	}
	return matched
}

// init sets up JMeter paths based on environment variables for version compatibility
func init() {
	// Get JMETER_BIN environment variable set by Dockerfile
	// Default to hardcoded path for backward compatibility
	jmeterBinFolder := os.Getenv("JMETER_BIN")
	if jmeterBinFolder == "" {
		// Fallback to legacy hardcoded path for JMeter 3.3
		jmeterBinFolder = "/apache-jmeter-3.3/bin"
		log.Println("setagaya-agent: JMETER_BIN not set, using legacy path:", jmeterBinFolder)
	} else {
		log.Println("setagaya-agent: Using JMETER_BIN from environment:", jmeterBinFolder)
	}

	// Validate the JMeter path for security
	if !validateJMeterPath(jmeterBinFolder) {
		log.Printf("setagaya-agent: WARNING - Invalid JMeter path detected: %s", jmeterBinFolder)
		// Fall back to safe default
		jmeterBinFolder = "/apache-jmeter-3.3/bin"
		log.Println("setagaya-agent: Using safe fallback path:", jmeterBinFolder)
	}

	// Set up dynamic paths using path.Join for security
	JMETER_EXECUTABLE = path.Join(jmeterBinFolder, JMETER_BIN)
	JMETER_SHUTDOWN = path.Join(jmeterBinFolder, "stoptest.sh")

	// Log final paths for debugging
	log.Printf("setagaya-agent: JMeter executable path: %s", JMETER_EXECUTABLE)
	log.Printf("setagaya-agent: JMeter shutdown path: %s", JMETER_SHUTDOWN)
}

const (
	RESULT_ROOT      = "/test-result"
	TEST_DATA_FOLDER = "/test-data"
	PROPERTY_FILE    = "/test-conf/setagaya.properties"
	JMETER_BIN       = "jmeter"
	STDERR           = "/dev/stderr"
	JMX_FILENAME     = "modified.jmx"
)

var (
	JMX_FILEPATH      = path.Join(TEST_DATA_FOLDER, JMX_FILENAME)
	JMETER_EXECUTABLE string
	JMETER_SHUTDOWN   string
)

type SetagayaWrapper struct {
	newClients     chan chan string
	closingClients chan chan string
	clients        map[chan string]bool
	closeSignal    chan int
	Bus            chan string
	logCounter     int
	httpClient     *http.Client
	pidLock        sync.RWMutex
	handlerLock    sync.RWMutex
	currentPid     int
	storageClient  sos.StorageInterface
	//stderr         io.ReadCloser
	reader       io.ReadCloser
	writer       io.Writer
	buffer       []byte
	runID        int
	collectionID string
	planID       string
	engineID     int
}

func findCollectionIDPlanID() (string, string) {
	return os.Getenv("collection_id"), os.Getenv("plan_id")
}

func NewServer() (sw *SetagayaWrapper) {
	// Instantiate a broker
	sw = &SetagayaWrapper{
		newClients:     make(chan chan string),
		closingClients: make(chan chan string),
		clients:        make(map[chan string]bool),
		closeSignal:    make(chan int),
		logCounter:     0,
		Bus:            make(chan string),
		httpClient:     &http.Client{},
		storageClient:  sos.Client.Storage,
	}
	sw.collectionID, sw.planID = findCollectionIDPlanID()
	reader, writer, err := os.Pipe()
	if err != nil {
		log.Printf("Error creating pipe: %v", err)
		return
	}
	mw := io.MultiWriter(writer, os.Stderr)
	sw.reader = reader
	sw.writer = mw
	log.SetOutput(mw)
	// Set it running - listening and broadcasting events
	go sw.listen()
	go sw.readOutput()
	return
}

func (sw *SetagayaWrapper) readOutput() {
	rd := bufio.NewReader(sw.reader)
	for {
		line, _, err := rd.ReadLine()
		if err != nil {
			continue
		}
		line = append(line, '\n')
		sw.buffer = append(sw.buffer, line...)
	}
}

func parseRawMetrics(rawLine string) (enginesModel.SetagayaMetric, error) {
	line := strings.Split(rawLine, "|")
	// We use char "|" as the separator in jmeter jtl file. If some users somehow put another | in their label name
	// we could end up a broken split. For those requests, we simply ignore otherwise the process will crash.
	// With current jmeter setup, we are expecting 12 items to be presented in the JTL file after split.
	// The column in the JTL files are:
	// timeStamp|elapsed|label|responseCode|responseMessage|threadName|success|bytes|grpThreads|allThreads|Latency|Connect
	if len(line) < 12 {
		log.Printf("line length was less than required. Raw line is %s", rawLine)
		return enginesModel.SetagayaMetric{}, fmt.Errorf("line length was less than required. Raw line is %s", rawLine)
	}
	label := line[2]
	status := line[3]
	threads, err := strconv.ParseFloat(line[9], 64)
	if err != nil {
		threads = 0 // default to 0 if parsing fails
		log.Printf("Error parsing threads from line[9] '%s': %v", line[9], err)
	}
	latency, err := strconv.ParseFloat(line[10], 64)
	if err != nil {
		return enginesModel.SetagayaMetric{}, err
	}
	return enginesModel.SetagayaMetric{
		Threads: threads,
		Label:   label,
		Status:  status,
		Latency: latency,
		Raw:     rawLine,
	}, nil
}

func (sw *SetagayaWrapper) makePromMetrics(line string) {
	metric, err := parseRawMetrics(line)
	// we need to pass the engine meta(project, collection, plan), especially run id
	// Run id is generated at controller side
	if err != nil {
		return
	}
	collectionID := sw.collectionID
	planID := sw.planID
	engineID := fmt.Sprintf("%d", sw.engineID)
	runID := fmt.Sprintf("%d", sw.runID)

	label := metric.Label
	status := metric.Status
	latency := metric.Latency
	threads := metric.Threads

	config.StatusCounter.WithLabelValues(sw.collectionID, planID, runID, engineID, label, status).Inc()
	config.CollectionLatencySummary.WithLabelValues(collectionID, runID).Observe(latency)
	config.PlanLatencySummary.WithLabelValues(collectionID, planID, runID).Observe(latency)
	config.LabelLatencySummary.WithLabelValues(collectionID, label, runID).Observe(latency)
	config.ThreadsGauge.WithLabelValues(collectionID, planID, runID, engineID).Set(threads)

}

func (sw *SetagayaWrapper) listen() {
	for {
		select {
		case s := <-sw.newClients:
			// A new client has connected.
			// Register their message channel
			sw.clients[s] = true
			log.Printf("setagaya-agent: Metric subscriber added. %d registered subscribers", len(sw.clients))
		case s := <-sw.closingClients:
			// A client has dettached and we want to
			// stop sending them messages.
			delete(sw.clients, s)
			close(s)
			log.Printf("setagaya-agent: Metric subscriber removed. %d registered subscribers", len(sw.clients))
		case event := <-sw.Bus:
			// We got a new event from the outside!
			// Send event to all connected clients
			sw.makePromMetrics(event)
			for clientMessageChan := range sw.clients {
				clientMessageChan <- event
			}
		}
	}
}

func (sw *SetagayaWrapper) makeLogFile() string {
	filename := fmt.Sprintf("kpi-%d.jtl", sw.logCounter)
	return path.Join(RESULT_ROOT, filename)
}

func (sw *SetagayaWrapper) tailJemeter() {
	var t *tail.Tail
	var err error
	logFile := sw.makeLogFile()
	for {
		t, err = tail.TailFile(logFile, tail.Config{MustExist: true, Follow: true, Poll: true})
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		break
	}
	// It's not thread safe. But we should be ok since we don't perform tests in parallel.
	sw.logCounter += 1
	log.Printf("setagaya-agent: Start tailing JTL file %s", logFile)
	for {
		select {
		case <-sw.closeSignal:
			if err := t.Stop(); err != nil {
				log.Printf("Error stopping tail: %v", err)
			}
			return
		case line := <-t.Lines:
			sw.Bus <- line.Text
		}
	}
}

func (sw *SetagayaWrapper) streamHandler(w http.ResponseWriter, r *http.Request) {
	messageChan := make(chan string)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return

	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Signal the sw that we have a new connection
	sw.newClients <- messageChan
	// Listen to connection close and un-register messageChan using context
	ctx := r.Context()

	go func() {
		<-ctx.Done()
		sw.closingClients <- messageChan
	}()

	for message := range messageChan {
		if message == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", message); err != nil {
			log.Printf("Error writing to response: %v", err)
		}
		flusher.Flush()
	}
}

func (sw *SetagayaWrapper) stopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		return
	}
	pid := sw.getPid()
	if pid == 0 {
		return
	}
	log.Printf("setagaya-agent: Shutting down Jmeter process %d", sw.getPid())

	// Validate shutdown command path for security
	if _, err := os.Stat(JMETER_SHUTDOWN); os.IsNotExist(err) {
		log.Printf("setagaya-agent: ERROR - JMeter shutdown script not found: %s", JMETER_SHUTDOWN)
		return
	}

	// #nosec G204 - JMETER_SHUTDOWN is validated and controlled by container environment
	cmd := exec.Command(JMETER_SHUTDOWN)
	if err := cmd.Run(); err != nil {
		log.Printf("Error running JMeter shutdown command: %v", err)
	}
	for sw.getPid() != 0 {
		time.Sleep(time.Second * 2)
	}
	sw.closeSignal <- 1
}

func (sw *SetagayaWrapper) setPid(pid int) {
	sw.pidLock.Lock()
	defer sw.pidLock.Unlock()

	sw.currentPid = pid
}

func (sw *SetagayaWrapper) getPid() int {
	sw.pidLock.RLock()
	defer sw.pidLock.RUnlock()

	return sw.currentPid
}

func (sw *SetagayaWrapper) runCommand() int {
	log.Printf("setagaya-agent: Start to run plan")

	// Validate JMeter executable exists for security
	if _, err := os.Stat(JMETER_EXECUTABLE); os.IsNotExist(err) {
		log.Printf("setagaya-agent: ERROR - JMeter executable not found: %s", JMETER_EXECUTABLE)
		return 0
	}

	// Validate required files exist
	if _, err := os.Stat(JMX_FILEPATH); os.IsNotExist(err) {
		log.Printf("setagaya-agent: ERROR - JMX test plan not found: %s", JMX_FILEPATH)
		return 0
	}

	logFile := sw.makeLogFile()

	// #nosec G204 - JMETER_EXECUTABLE and arguments are validated and controlled by container environment
	cmd := exec.Command(JMETER_EXECUTABLE, "-n", "-t", JMX_FILEPATH, "-l", logFile,
		"-q", PROPERTY_FILE, "-G", PROPERTY_FILE, "-j", STDERR)
	cmd.Stderr = sw.writer
	err := cmd.Start()
	if err != nil {
		log.Println(err)
		return 0
	}
	pid := cmd.Process.Pid
	sw.setPid(pid)
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("setagaya-agent: Error waiting for command: %v", err)
		}
		log.Printf("setagaya-agent: Shutdown is finished, resetting pid to zero")
		sw.setPid(0)
	}()
	return pid
}

func cleanTestData() error {
	if err := os.RemoveAll(TEST_DATA_FOLDER); err != nil {
		return err
	}
	if err := os.MkdirAll(TEST_DATA_FOLDER, 0750); err != nil {
		return err
	}
	return nil
}

func saveToDisk(filename string, file []byte) error {
	// Sanitize filename to prevent path traversal attacks
	cleanFilename := filepath.Base(filename)
	if cleanFilename == "." || cleanFilename == ".." || strings.Contains(cleanFilename, "..") {
		return errors.New("invalid filename")
	}

	filePath := filepath.Join(TEST_DATA_FOLDER, cleanFilename)

	// Sanitize log output to prevent log injection
	sanitizedPath := strings.ReplaceAll(filePath, "\n", "")
	sanitizedPath = strings.ReplaceAll(sanitizedPath, "\r", "")
	log.Printf("Saving file to: %s", sanitizedPath)

	// Use secure file permissions instead of 0777
	if err := os.WriteFile(filePath, file, 0600); err != nil {
		return err
	}
	return nil
}

func GetThreadGroups(planDoc *etree.Document) ([]*etree.Element, error) {
	jtp := planDoc.SelectElement("jmeterTestPlan")
	if jtp == nil {
		return nil, errors.New("missing Jmeter Test plan in jmx")
	}
	ht := jtp.SelectElement("hashTree")
	if ht == nil {
		return nil, errors.New("missing hash tree inside Jmeter test plan in jmx")
	}
	ht = ht.SelectElement("hashTree")
	if ht == nil {
		return nil, errors.New("missing hash tree inside hash tree in jmx")
	}
	tgs := ht.SelectElements("ThreadGroup")
	stgs := ht.SelectElements("SetupThreadGroup")
	tgs = append(tgs, stgs...)
	return tgs, nil
}

func parseTestPlan(file []byte) (*etree.Document, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(file); err != nil {
		return nil, err
	}
	return doc, nil
}

func modifyJMX(file []byte, threads, duration, rampTime string) ([]byte, error) {
	planDoc, err := parseTestPlan(file)
	if err != nil {
		return nil, err
	}
	durationInt, err := strconv.Atoi(duration)
	if err != nil {
		return nil, err
	}
	// it includes threadgroups and setupthreadgroups
	threadGroups, err := GetThreadGroups(planDoc)
	if err != nil {
		return nil, err
	}
	for _, tg := range threadGroups {
		children := tg.ChildElements()
		for _, child := range children {
			attrName := child.SelectAttrValue("name", "")
			switch attrName {
			case "ThreadGroup.duration":
				child.SetText(strconv.Itoa(durationInt * 60))
			case "ThreadGroup.scheduler":
				child.SetText("true")
			case "ThreadGroup.num_threads":
				child.SetText(threads)
			case "ThreadGroup.ramp_time":
				child.SetText(rampTime)
			}
		}
	}
	return planDoc.WriteToBytes()
}

func (sw *SetagayaWrapper) prepareJMX(sf *model.SetagayaFile, threads, duration, rampTime string) error {
	file, err := sw.storageClient.Download(sf.Filepath)
	if err != nil {
		log.Println(err)
		return err
	}
	modified, err := modifyJMX(file, threads, duration, rampTime)
	if err != nil {
		return err
	}
	return saveToDisk(JMX_FILENAME, modified)
}

func (sw *SetagayaWrapper) prepareCSV(sf *model.SetagayaFile) error {
	file, err := sw.storageClient.Download(sf.Filepath)
	if err != nil {
		return err
	}
	splittedCSV, err := utils.SplitCSV(file, sf.TotalSplits, sf.CurrentSplit)
	if err != nil {
		return err
	}
	return saveToDisk(sf.Filename, splittedCSV)
}

func (sw *SetagayaWrapper) downloadAndSaveFile(sf *model.SetagayaFile) error {
	file, err := sw.storageClient.Download(sf.Filepath)
	if err != nil {
		return err
	}
	return saveToDisk(sf.Filename, file)
}

func (sw *SetagayaWrapper) prepareTestData(edc enginesModel.EngineDataConfig) error {
	for _, sf := range edc.EngineData {
		fileType := filepath.Ext(sf.Filename)
		switch fileType {
		case ".jmx":
			if err := sw.prepareJMX(sf, edc.Concurrency, edc.Duration, edc.Rampup); err != nil {
				return err
			}
		case ".csv":
			if err := sw.prepareCSV(sf); err != nil {
				return err
			}
		default:
			if err := sw.downloadAndSaveFile(sf); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sw *SetagayaWrapper) startHandler(w http.ResponseWriter, r *http.Request) {
	sw.handlerLock.Lock()
	defer sw.handlerLock.Unlock()

	if r.Method == "POST" {
		if sw.getPid() != 0 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		file, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Printf("Error closing request body: %v", err)
			}
		}()
		var edc enginesModel.EngineDataConfig
		if err := json.Unmarshal(file, &edc); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := cleanTestData(); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := sw.prepareTestData(edc); err != nil {
			if errors.Is(err, sos.FileNotFoundError()) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sw.runID = int(edc.RunID)
		sw.engineID = edc.EngineID
		pid := sw.runCommand()
		go sw.tailJemeter()
		log.Printf("setagaya-agent: Start running Jmeter process with pid: %d", pid)
		if _, err := w.Write([]byte(strconv.Itoa(pid))); err != nil {
			log.Printf("Error writing PID response: %v", err)
		}
		return
	}
	if _, err := w.Write([]byte("hmm")); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func (sw *SetagayaWrapper) progressHandler(w http.ResponseWriter, r *http.Request) {
	pid := sw.getPid()
	if pid == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (sw *SetagayaWrapper) stdoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write(sw.buffer); err != nil {
		log.Printf("Error writing stdout response: %v", err)
	}
}

// This func reports the cpu/memory usage of the engine
// It will run when the engine is started until it's finished.
func (sw *SetagayaWrapper) reportOwnMetrics(interval time.Duration) error {
	prev := uint64(0)
	engineNumber := strconv.Itoa(sw.engineID)
	for {
		time.Sleep(interval)
		cpuUsage, err := containerstats.ReadCPUUsage()
		if err != nil {
			return err
		}
		if prev == 0 {
			prev = cpuUsage
			continue
		}
		used := (cpuUsage - prev) / uint64(interval.Seconds()) / 1000
		prev = cpuUsage
		memoryUsage, err := containerstats.ReadMemoryUsage()
		if err != nil {
			return err
		}
		config.CpuGauge.WithLabelValues(sw.collectionID,
			sw.planID, engineNumber).Set(float64(used))
		config.MemGauge.WithLabelValues(sw.collectionID,
			sw.planID, engineNumber).Set(float64(memoryUsage))
	}
}

func main() {
	sw := NewServer()
	go func() {
		if err := sw.reportOwnMetrics(5 * time.Second); err != nil {
			// if the engine is having issues with reading stats from cgroup
			// we should fast fail to detect the issue. It could be due to
			// kernel change
			log.Fatal(err)
		}
	}()
	http.HandleFunc("/start", sw.startHandler)
	http.HandleFunc("/stop", sw.stopHandler)
	http.HandleFunc("/stream", sw.streamHandler)
	http.HandleFunc("/progress", sw.progressHandler)
	http.HandleFunc("/output", sw.stdoutHandler)
	http.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)

	// Create HTTP server with timeouts for security
	server := &http.Server{
		Addr:           ":8080",
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	log.Fatal(server.ListenAndServe())
}
