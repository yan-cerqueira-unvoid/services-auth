package controllers

import (
	"net/http"
	"runtime"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type PrometheusController struct {
	Handler http.Handler
	Logger  *logrus.Logger
}

func NewPrometheusController(logger  *logrus.Logger) *PrometheusController {
	virtualMemory, err := mem.VirtualMemory()
	if err != nil {
		logger.WithError(err)
	}
	totalMemoryGB := float64(virtualMemory.Total) / (1024 * 1024 * 1024)

	memUsage := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "current_memory_usage_gbytes",
		Help: "Current memory usage in bytes (allocated heap)",
	}, func() float64 {

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		usedMemory := float64(m.Alloc) / (1 << 30) // Memory currently allocated and in-use (heap) in GB

		return usedMemory
	})

	memTotal := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "total_memory_gbytes",
		Help: "Total node memory in Gb",
	}, func() float64 {
		return totalMemoryGB
	})

	cpuUsage := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cpu_usage",
		Help: "Percentage of cpu usage per second",
	}, func() float64 {
		percent, err := cpu.Percent(1*time.Second, false) // 'false' for overall CPU usage (all cores)
		if err != nil {
			logger.WithError(err)
		}
		return percent[0]
	})

	prometheus.MustRegister(memUsage,
		memTotal,
		cpuUsage)

	return &PrometheusController{
		Handler: promhttp.Handler(),
		Logger:  logger,
	}
}

func (controller *PrometheusController) HandleMain() gin.HandlerFunc {
	return func(c *gin.Context) {
		controller.Handler.ServeHTTP(c.Writer, c.Request)
	}
}
