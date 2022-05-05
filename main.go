package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hillu/go-yara/v4"
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/sqooba/go-common/healthchecks"
	"github.com/sqooba/go-common/logging"
	"github.com/sqooba/go-common/version"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	healthCheck = flag.Bool("health-check", false, "Run health-check")
	setLogLevel = flag.String("set-log-level", "", "Change log level. Possible values are trace,debug,info,warn,error,fatal,panic")
	log         = logging.NewLogger()
)

type envConfig struct {
	YaraRulesDir string `envconfig:"YARA_RULES_DIR"`
	Port         string `envconfig:"PORT" default:"8080"`
	LogLevel         string `envconfig:"LOG_LEVEL_TEST" default:"info"`
	MetricsNamespace string `envconfig:"METRICS_NAMESPACE" default:"metis"`
	MetricsSubsystem string `envconfig:"METRICS_SUBSYSTEM" default:"yararestapi"`
	MetricsPath      string `envconfig:"METRICS_PATH" default:"/metrics"`
}

func main() {

	log.Println("Yara-rest-api application is starting...")
	log.Printf("Version    : %s", version.Version)
	log.Printf("Commit     : %s", version.GitCommit)
	log.Printf("Build date : %s", version.BuildDate)
	log.Printf("OSarch     : %s", version.OsArch)

	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Errorf("Failed to process env var: %s", err)
		return
	}

	flag.Parse()
	err := logging.SetLogLevel(log, env.LogLevel)
	if err != nil {
		log.Errorf("Logging level %s do not seem to be right. Err = %v", env.LogLevel, err)
		return
	}

	// Running health check (so that it can be the same binary in the containers
	if *healthCheck {
		healthchecks.RunHealthCheckAndExit(env.Port)
	}
	if *setLogLevel != "" {
		logging.SetRemoteLogLevelAndExit(log, env.Port, *setLogLevel)
	}

	router := mux.NewRouter().StrictSlash(true)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	rules, err := loadRulesFromDir(env.YaraRulesDir)
	if err != nil {
		log.Errorf("Got an error while loading yara rules from dir %s, err = %v", env.YaraRulesDir, err)
		return
	}

	log.Infof("Successfully loaded %d rules from dir %s, err = %v", len(rules.GetRules()), env.YaraRulesDir, err)

	scanner, err := yara.NewScanner(rules)
	if err != nil {
		log.Errorf("Got an error while loading yara scanner from rules, err = %v", err)
		return
	}

	// curl http://localhost:8080/yara -F "sample=@test.txt" -vvv
	router.HandleFunc("/yara", ScanFile(scanner)).Methods("POST")

	// curl http://localhost:8080/debug/rules -vvv
	router.HandleFunc("/debug/rules", ListRules(rules)).Methods("GET")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})

	err = http.ListenAndServe(fmt.Sprintf("0.0.0.0:%s", env.Port), c.Handler(router))
	if err != nil {
		log.Errorf("Got an error %v", err)
	}
}

func logWhenError(f func() error, label string, log *logrus.Logger) func() error {
	return func() error {
		err := f()
		if err != nil && err != context.Canceled {
			log.Warnf("Got an error in %s: err = %v", label, err)
		}
		return err
	}
}

func ScanFile(scanner *yara.Scanner) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(32 << 24) // 512 MB
		if err != nil {
			log.Errorf("Got an error while parsing multipart form, err = %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{\"error\": \"\", \"reason\":\"\"}"))
			return
		}

		file, header, err := r.FormFile("sample")
		if err != nil {
			log.Errorf("Got an error while getting file %s from form, err = %v", header.Filename, err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{\"error\": \"\", \"reason\":\"\"}"))
			return
		}
		defer file.Close()

		var buf bytes.Buffer
		_, err = io.Copy(&buf, file)
		if err != nil {
			log.Errorf("Got an error copying file to buf, err = %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("{\"error\": \"\", \"reason\":\"\"}"))
			return
		}

		var m yara.MatchRules
		err = scanner.SetCallback(&m).ScanMem(buf.Bytes())
		if err != nil {
			log.Errorf("Got an error scanning mem %d, err = %v", header.Filename, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("{\"error\": \"\", \"reason\":\"\"}"))
			return
		}

		// Filter via namespace is provided
		filteredNamespaces, hasNamespace := r.Form["namespace"]
		matchRuleNames := make([]string, 0, len(m))
		for _, rule := range m {
			if !hasNamespace || stringArrayContains(filteredNamespaces, rule.Namespace) {
				matchRuleNames = append(matchRuleNames, filepath.Join(rule.Namespace, rule.Rule))
			}
		}

		jsonMatchRuleNames, _ := json.Marshal(matchRuleNames)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("{\"matchingRules\": %s}", jsonMatchRuleNames)))
		return
	}
}

func ListRules(rules *yara.Rules) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleNames := make([]string, 0, len(rules.GetRules()))
		for _, rule := range rules.GetRules() {
			ruleNames = append(ruleNames, filepath.Join(rule.Namespace(), rule.Identifier()))
		}
		jsonRuleNames, _ := json.Marshal(ruleNames)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("{\"rules\": %s}", jsonRuleNames)))
	}
}

func stringArrayContains(array []string, elmt string) bool {
	for _, a := range array {
		if elmt == a {
			return true
		}
	}
	return false
}

func loadRulesFromDir(yaraRulesDir string) (*yara.Rules, error) {

	c, err := yara.NewCompiler()
	if c == nil || err != nil {
		log.Errorf("Go an error while instanciating a new yara compiler, err = %v", err)
		return nil, err
	}

	rulesCount := 0

	err = filepath.Walk(yaraRulesDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			log.Debugf("Got an error while opening %s, Err = %v", path, err)
			return err
		}
		namespace := filepath.Base(filepath.Dir(strings.TrimPrefix(path, yaraRulesDir)))
		if namespace == "." {
			namespace = ""
		}
		if err = c.AddFile(f, namespace); err != nil {
			log.Debugf("Got an error while adding yara file %s, err = %v", f.Name(), err)
			return err
		}
		rulesCount++
		return nil
	})

	if err != nil {
		log.Debugf("Got an error while adding yara files from dir %s, err = %v", yaraRulesDir, err)
		return nil, err
	}

	rules, err := c.GetRules()
	if err != nil {
		log.Debugf("Got an error while getting rules from yara compiler, err = %v", err)
		return nil, err
	}

	return rules, nil
}
