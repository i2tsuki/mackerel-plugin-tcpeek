package mptcpeek

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	mp "github.com/mackerelio/go-mackerel-plugin"
	"github.com/pkg/errors"
)

var timeout = 3 * time.Second

// // TcpeekPrometheusMetric is metric for tcpeek
// type TcpeekPrometheusMetric struct {
// 	Success TcpeekPrometheusSuccess
// 	Failure TcpeekPrometheusFailure
// }

// // TcpeekPrometheusSuccess is metric for tcpeek
// type TcpeekPrometheusSuccess struct {
// 	Total     prometheus.Gauge
// 	DupSyn    prometheus.Gauge
// 	DupSynAck prometheus.Gauge
// }

// // TcpeekPrometheusFailure is metric for tcpeek
// type TcpeekPrometheusFailure struct {
// 	Total   prometheus.Gauge
// 	Timeout prometheus.Gauge
// 	Reject  prometheus.Gauge
// 	Unreach prometheus.Gauge
// }

// TcpeekPlugin mackerel plugin for tcpeek
type TcpeekPlugin struct {
	Socket string
	Prefix string
}

// TcpeekMetric is metric for tcpeek
type TcpeekMetric struct {
	Success TcpeekSuccess `json:"success"`
	Failure TcpeekFailure `json:"failure"`
}

// TcpeekSuccess is statistics for tcpeek
type TcpeekSuccess struct {
	Total     int64 `json:"total"`
	DupSyn    int64 `json:"dupsyn"`
	DupSynAck int64 `json:"dupsynack"`
}

// TcpeekFailure is statistics for tcpeek
type TcpeekFailure struct {
	Total   int64 `json:"total"`
	Timeout int64 `json:"timeout"`
	Reject  int64 `json:"reject"`
	Unreach int64 `json:"unreach"`
}

// TcpeekPcapStats is statistics for tcpeek pcap
type TcpeekPcapStats struct {
	Recv   int64 `json:"recv"`
	Drop   int64 `json:"drop"`
	Ifdrop int64 `json:"ifdrop"`
}

// TcpeekStat sturct for statistics for tcpeek
type TcpeekStat []map[string]TcpeekMetric

// FetchMetrics interface for mackerelplugin
func (p TcpeekPlugin) FetchMetrics() (map[string]float64, error) {
	var status TcpeekStat
	stat := make(map[string]float64)

	if strings.HasPrefix(p.Socket, "unix://") {
		conn, err := net.DialTimeout("unix", strings.TrimPrefix(p.Socket, "unix://"), timeout)
		if err != nil {
			fmt.Printf("err: %v", err)
			return stat, nil
		}
		defer conn.Close()

		fmt.Fprintf(conn, "REFRESH\r\n")
		dec := json.NewDecoder(conn)
		dec.Decode(&status)

		for _, value := range status {
			for k, v := range value {
				if k == "pcap" {
					continue
				} else {
					stat[k+"_success_total"] = float64(v.Success.Total)
					stat[k+"_success_dupsyn"] = float64(v.Success.DupSyn)
					stat[k+"_success_dupsynack"] = float64(v.Success.DupSynAck)

					stat[k+"_failure_total"] = float64(v.Failure.Total)
					stat[k+"_failure_timeout"] = float64(v.Failure.Timeout)
					stat[k+"_failure_reject"] = float64(v.Failure.Reject)
					stat[k+"_failure_unreach"] = float64(v.Failure.Unreach)
				}
			}
		}
	} else {
		err := errors.New("'--socket' is neither http endpoint nor the unix domain socket, try '--help' for more information")
		return nil, err
	}

	return stat, nil
}

// GraphDefinition interface for mackerelplugin
func (p TcpeekPlugin) GraphDefinition() map[string]mp.Graphs {
	labelPrefix := strings.Title(p.Prefix)
	graphdef := make(map[string]mp.Graphs)
	var status TcpeekStat

	if strings.HasPrefix(p.Socket, "unix://") {
		conn, err := net.DialTimeout("unix", strings.TrimPrefix(p.Socket, "unix://"), timeout)
		if err != nil {
			fmt.Printf("err: %v", err)
			return nil
		}
		defer conn.Close()

		fmt.Fprintf(conn, "REFRESH\r\n")
		dec := json.NewDecoder(conn)
		dec.Decode(&status)
	}

	for _, value := range status {
		for k, _ := range value {
			if k == "pcap" {
				continue
			}
			graphdef[k+".success"] = mp.Graphs{
				Label: labelPrefix + " " + k + " Success Count",
				Unit:  "integer",
				Metrics: []mp.Metrics{
					{Name: k + "_success_total", Label: "Total", Diff: false, Stacked: false},
					{Name: k + "_success_dupsyn", Label: "DupSyn", Diff: false, Stacked: false},
					{Name: k + "_success_dupsynack", Label: "DupSynAck", Diff: false, Stacked: false},
				},
			}
			graphdef[k+".failure"] = mp.Graphs{
				Label: labelPrefix + " " + k + " Failure Count",
				Unit:  "integer",
				Metrics: []mp.Metrics{
					{Name: k + "_failure_total", Label: "Total", Diff: false, Stacked: false},
					{Name: k + "_failure_timeout", Label: "Timeout", Diff: false, Stacked: false},
					{Name: k + "_failure_reject", Label: "Reject", Diff: false, Stacked: false},
					{Name: k + "_failure_unreach", Label: "Unreach", Diff: false, Stacked: false},
				},
			}
		}
	}

	return graphdef
}

// MetricKeyPrefix interface for PluginWithPrefix
func (p TcpeekPlugin) MetricKeyPrefix() string {
	if p.Prefix == "" {
		p.Prefix = "tcpeek"
	}
	return p.Prefix
}

// Do the plugin
func Do() {
	optSocket := flag.String("socket", "", "Socket (must be with prefix of 'unix://')")
	optPrefix := flag.String("metric-key-prefix", "", "Prefix")
	flag.Parse()

	tcpeek := TcpeekPlugin{Socket: *optSocket, Prefix: *optPrefix}

	helper := mp.NewMackerelPlugin(tcpeek)
	helper.Run()
}
