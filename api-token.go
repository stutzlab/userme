package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

func (h *HTTPServer) setupTokenHandlers() {
	h.router.POST("/token", tokenCreate())
	h.router.POST("/token/refresh", tokenRefresh())
	h.router.GET("/token", tokenInfo())
}

func tokenCreate() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "POST"
		ppath := "/token"

		m := make(map[string]string)
		data, _ := ioutil.ReadAll(c.Request.Body)
		err := json.Unmarshal(data, &m)
		if err != nil {
			c.JSON(400, gin.H{"message": fmt.Sprintf("Couldn't parse body contents. err=%s", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
			return
		}

		email, em := m["email"]
		password, ep := m["password"]
		if !em || !ep {
			c.JSON(400, gin.H{"message": "Couldn't get email/password from body contents"})
			invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
			return
		}

		phash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		var u User
		db1 := db.First(&u, "email = ? AND password_hash = ? AND activation_date IS NOT NULL", email, phash)

		if db1.RecordNotFound() {
			c.JSON(450, gin.H{"message": "Email/password combination not valid"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		if db1.Error != nil {
			logrus.Warnf("Error authenticating user %s. err=%s", email, db1.Error)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		validateUserAndOutputTokensToResponse(&u, c, pmethod, ppath)
		logrus.Debugf("Token creation for %s", email)
	}
}

func tokenRefresh() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "POST"
		ppath := "/token/refresh"

		claims, err := loadAndValidateToken(c.Request, "refresh", "")
		if err != nil {
			c.JSON(450, gin.H{"message": "Invalid refresh token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		email, exists := claims["sub"]
		if !exists {
			logrus.Warnf("Refresh token valid but doesn't have 'sub' claim")
			c.JSON(450, gin.H{"message": "Invalid refresh token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		logrus.Debugf("Refresh token validated for %s. Verifying user account", email)

		var u User
		db1 := db.First(&u, "email = ? AND activation_date IS NOT NULL", email)
		if db1.RecordNotFound() {
			c.JSON(404, gin.H{"message": "Account not found"})
			invocationCounter.WithLabelValues(pmethod, ppath, "404").Inc()
			return
		}
		err = db1.Error
		if err != nil {
			logrus.Warnf("Error getting user during token refresh. email=%s err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		validateUserAndOutputTokensToResponse(&u, c, pmethod, ppath)
		logrus.Debugf("Token refresh for %s", email)
	}
}

func tokenInfo() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "GET"
		ppath := "/token"

		claims, err := loadAndValidateToken(c.Request, "access", "")
		if err != nil {
			c.JSON(450, gin.H{"message": "Invalid access token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		email, exists := claims["sub"]
		if !exists {
			c.JSON(450, gin.H{"message": "Invalid access token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		var u User
		db1 := db.First(&u, "email = ? AND activation_date IS NOT NULL AND enabled = 1", email)

		if db1.RecordNotFound() {
			c.JSON(455, gin.H{"message": "User not enabled"})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return
		}

		if db1.Error != nil {
			logrus.Warnf("Error finding user %s. err=%s", email, db1.Error)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		c.JSON(200, claims)
		invocationCounter.WithLabelValues(pmethod, ppath, "200").Inc()
		logrus.Debugf("Token info for %s", email)
	}
}

func validateUserAndOutputTokensToResponse(u *User, c *gin.Context, pmethod string, ppath string) {
	if u.Enabled == 0 {
		c.JSON(460, gin.H{"message": "Account disabled"})
		invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
		return
	}

	if u.PasswordValidUntil != nil {
		if u.PasswordValidUntil.Before(time.Now()) {
			c.JSON(455, gin.H{"message": "Password expired"})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return
		}
	}

	logrus.Debugf("User %s authenticated and validated")
	tokensResponse, err := createAccessAndRefreshToken(u.Name, u.Email, opt.accessTokenDefaultScope)
	if err != nil {
		logrus.Warnf("Error generating tokens for user %s. err=%s", u.Email, err)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	c.JSON(200, tokensResponse)
	invocationCounter.WithLabelValues(pmethod, ppath, "200").Inc()
	logrus.Debugf("Tokens for %s generated and sent to response")
}
