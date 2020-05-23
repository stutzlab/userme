package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	// "github.com/dgrijalva/jwt-go"
)

func (h *HTTPServer) setupTokenHandlers() {
	// h.router.GET("/backup/:name/materialized", ListMaterizalized())
	// h.router.POST("/backup/:name/materialized", TriggerBackup())
}

//ListMaterizalized get currently tracked backups
func BBB() func(*gin.Context) {
	return func(c *gin.Context) {
		logrus.Debugf("ListMaterizalized")
		tag := c.Query("tag")
		status := c.Query("status")
		name := c.Param("name")

		backups, err := getMaterializedBackups(name, 0, tag, status, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": fmt.Sprintf("Error getting materialized. err=%s", err)})
			apiInvocationsCounter.WithLabelValues("materialized", "error").Inc()
			return
		}

		apiInvocationsCounter.WithLabelValues("materialized", "success").Inc()
		c.JSON(http.StatusOK, backups)
	}
}
