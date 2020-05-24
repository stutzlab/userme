package main

import (
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	// uuid "github.com/satori/go.uuid"

	cors "github.com/itsjamie/gin-cors"
)

type HTTPServer struct {
	server *http.Server
	router *gin.Engine
}

var invocationCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "api_invocations_total",
	Help: "Total api requests served",
}, []string{
	"method",
	"path",
	"status",
})

var mailCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mail_sent_total",
	Help: "Total e-mails sent",
}, []string{
	"status",
})

func NewHTTPServer() *HTTPServer {
	router := gin.Default()

	router.Use(cors.Middleware(cors.Config{
		Origins:         opt.corsAllowedOrigins,
		Methods:         "GET, POST",
		RequestHeaders:  "Origin, Content-Type",
		ExposedHeaders:  "",
		MaxAge:          24 * 3600 * time.Second,
		Credentials:     false,
		ValidateHeaders: false,
	}))

	h := &HTTPServer{server: &http.Server{
		Addr:    ":6000",
		Handler: router,
	}, router: router}

	prometheus.MustRegister(invocationCounter)
	prometheus.MustRegister(mailCounter)

	logrus.Infof("Initializing HTTP Handlers...")
	h.setupUserHandlers()
	h.setupTokenHandlers()
	h.setupPasswordHandlers()
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return h
}

//Start the main HTTP Server entry
func (s *HTTPServer) Start() error {
	logrus.Infof("Starting HTTP Server on port 6000")
	return s.server.ListenAndServe()
}

func validateField(m map[string]string, fieldName string, regex string) bool {
	v, exists := m[fieldName]
	if !exists {
		return false
	}
	re := regexp.MustCompile(regex)
	return re.MatchString(v)
}
