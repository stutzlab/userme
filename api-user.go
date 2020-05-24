package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

func (h *HTTPServer) setupUserHandlers() {
	h.router.PUT("/user/:email", createUser())
	// h.router.POST("/user/:email/activate", activateUser())
	// h.router.POST("/user/:email/disable", disableUser())
}

func createUser() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "PUT"
		ppath := "/user/:email"

		email := strings.ToLower(c.Param("email"))
		logrus.Debugf("createUser email=%s", email)

		// * 201 - user created and activated
		// * 250 - user created and activation link sent to email

		m := make(map[string]string)
		data, _ := ioutil.ReadAll(c.Request.Body)
		err := json.Unmarshal(data, &m)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("Couldn't parse body contents. err=%s", err)})
			invocationCounter.WithLabelValues("PUT", "/user/:email", "500").Inc()
			return
		}
		m["email"] = email

		//VALIDATE INPUTS
		valid := validateField(m, "email", "^(([^<>()\\[\\]\\.,;:\\s@\"]+(\\.[^<>()\\[\\]\\.,;:\\s@\"]+)*)|(\".+\"))@(([^<>()[\\]\\.,;:\\s@\"]+\\.)+[^<>()[\\]\\.,;:\\s@\"]{2,})$")
		if !valid {
			c.JSON(450, gin.H{"message": fmt.Sprintf("Invalid email", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return
		}

		valid = validateField(m, "name", "^.{4,}$")
		if !valid {
			c.JSON(450, gin.H{"message": fmt.Sprintf("Invalid name", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		valid = validateField(m, "password", opt.passwordValidationRegex)
		if !valid {
			c.JSON(460, gin.H{"message": fmt.Sprintf("Invalid password", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
			return
		}

		//VERIFY IF EMAIL ALREADY EXISTS
		var u User
		if !db.First(&u, "email = ?", email).RecordNotFound() {
			if u.activationDate != nil {
				logrus.Infof("Account creation: email '%s' already registered", email)
				c.JSON(455, gin.H{"message": fmt.Sprintf("Invalid email", err)})
				invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
				return
			}

			logrus.Infof("New account registration with existing email in pending activation state. Replacing it.")
			err := db.Unscoped().Delete(&u).Error
			if err != nil {
				logrus.Warnf("Couldn't delete user email=%s", email)
				c.JSON(500, gin.H{"message": fmt.Sprintf("Server error", err)})
				invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
				return
			}
		}

		//CREATE ACCOUNT
		pwd := m["password"]
		phash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
		if err != nil {
			logrus.Warnf("Couldn't hash password for email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": fmt.Sprintf("Server error", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		u0 := User{
			email:          email,
			active:         1,
			creationDate:   time.Now(),
			name:           m["name"],
			passwordDate:   time.Now(),
			passwordHash:   string(phash),
			activationDate: nil,
		}
		if opt.accountActivationMethod == "direct" {
			now := time.Now()
			u0.activationDate = &now
		}
		err = db.Create(&u0).Error
		if err != nil {
			logrus.Warnf("Error creating user email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": fmt.Sprintf("Server error", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		if opt.accountActivationMethod == "direct" {
			c.JSON(201, gin.H{"message": fmt.Sprintf("Account created and activated", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "201").Inc()
			return
		}

		//SEND ACTIVATION TOKEN TO USER EMAIL
		activationToken, err := createJWTToken(email, 5, "activate-user")
		if err != nil {
			logrus.Warnf("Error creating activation token for email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": fmt.Sprintf("Server error", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		logrus.Debugf("Sending activation mail to %s", email)
		htmlBody := strings.ReplaceAll(opt.mailActivationHTMLBody, "DISPLAY_NAME", u0.name)
		htmlBody = strings.ReplaceAll(htmlBody, "DISPLAY_NAME", u0.name)
		err = sendMail(opt.mailActivationSubject, "ACTIVATION_TOKEN", activationToken)
		if err != nil {
			logrus.Warnf("Couldn't send email to %s (%s). err=%s", email, opt.mailActivationSubject, err)
			mailCounter.WithLabelValues("500").Inc()
			return
		}
		mailCounter.WithLabelValues("200").Inc()
	}
}
