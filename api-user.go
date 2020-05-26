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
	h.router.POST("/user/:email/activate", activateUser())
	// h.router.POST("/user/:email/disable", disableUser())
}

func createUser() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "PUT"
		ppath := "/user/:email"

		email := strings.ToLower(c.Param("email"))
		logrus.Debugf("createUser email=%s", email)

		m := make(map[string]string)
		data, _ := ioutil.ReadAll(c.Request.Body)
		err := json.Unmarshal(data, &m)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("Couldn't parse body contents. err=%s", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}
		m["email"] = email

		//VALIDATE INPUTS
		valid := validateField(m, "email", "^(([^<>()\\[\\]\\.,;:\\s@\"]+(\\.[^<>()\\[\\]\\.,;:\\s@\"]+)*)|(\".+\"))@(([^<>()[\\]\\.,;:\\s@\"]+\\.)+[^<>()[\\]\\.,;:\\s@\"]{2,})$")
		if !valid {
			c.JSON(450, gin.H{"message": "Invalid email"})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return
		}

		valid = validateField(m, "name", "^.{4,}$")
		if !valid {
			c.JSON(450, gin.H{"message": "Invalid name"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		valid = validateField(m, "password", opt.passwordValidationRegex)
		if !valid {
			c.JSON(460, gin.H{"message": "Invalid password"})
			invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
			return
		}

		//VERIFY IF EMAIL ALREADY EXISTS
		var u User
		if !db.First(&u, "email = ?", email).RecordNotFound() {
			if u.ActivationDate != nil {
				c.JSON(465, gin.H{"message": "Email already registered"})
				invocationCounter.WithLabelValues(pmethod, ppath, "465").Inc()
				return
			}

			logrus.Infof("New account registration with existing email in pending activation state. Replacing it.")
			err := db.Unscoped().Delete(&u).Error
			if err != nil {
				logrus.Warnf("Couldn't delete user email=%s. err=%s", email, err)
				c.JSON(500, gin.H{"message": "Server error"})
				invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
				return
			}
		}

		//CREATE ACCOUNT
		pwd := m["password"]
		phash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
		if err != nil {
			logrus.Warnf("Couldn't hash password for email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		u0 := User{
			Email:              email,
			Enabled:            1,
			CreationDate:       time.Now(),
			Name:               m["name"],
			PasswordDate:       time.Now(),
			PasswordHash:       string(phash),
			ActivationDate:     nil,
			PasswordValidUntil: generatePasswordValidUntil(),
		}
		if opt.accountActivationMethod == "direct" {
			now := time.Now()
			u0.ActivationDate = &now
		}
		err = db.Create(&u0).Error
		if err != nil {
			logrus.Warnf("Error creating user email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		if opt.accountActivationMethod == "direct" {
			c.JSON(201, gin.H{"message": "Account created and activated"})
			invocationCounter.WithLabelValues(pmethod, ppath, "201").Inc()
			return
		}

		//SEND ACTIVATION TOKEN TO USER EMAIL
		_, activationTokenString, err := createJWTToken(email, opt.validationTokenExpirationMinutes, "activation", "")
		if err != nil {
			logrus.Warnf("Error creating activation token for email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		logrus.Debugf("Sending activation mail to %s", email)
		htmlBody := strings.ReplaceAll(opt.mailActivationHTMLBody, "$DISPLAY_NAME", u0.Name)
		htmlBody = strings.ReplaceAll(htmlBody, "$ACTIVATION_TOKEN", activationTokenString)
		err = sendMail(opt.mailActivationSubject, htmlBody, email, u0.Name)
		if err != nil {
			logrus.Warnf("Couldn't send account validation email to %s (%s). err=%s", email, opt.mailActivationSubject, err)
			mailCounter.WithLabelValues("POST", "activation", "500").Inc()
			c.JSON(500, gin.H{"message": "Server error"})
			return
		}

		logrus.Debugf("Account created and activation link sent to email %s", email)
		logrus.Debugf("Activation token=%s", activationTokenString)
		mailCounter.WithLabelValues("POST", "activation", "202").Inc()
		c.JSON(250, gin.H{"message": "Account created and activation link sent to email"})
		invocationCounter.WithLabelValues(pmethod, ppath, "250").Inc()
		return
	}
}

func activateUser() func(*gin.Context) {
	// * response body json: name, jwtAccessToken, jwtRefreshToken, accessTokenExpirationDate, refreshTokenExpirationDate
	return func(c *gin.Context) {
		pmethod := "POST"
		ppath := "/user/:email/activate"

		email := strings.ToLower(c.Param("email"))
		logrus.Debugf("activateUser email=%s", email)

		_, err := loadAndValidateToken(c.Request, "activation", email)
		if err != nil {
			c.JSON(450, gin.H{"message": "Invalid activation token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		var u User
		db1 := db.First(&u, "email = ?", email)
		if db1.RecordNotFound() {
			c.JSON(404, gin.H{"message": "Account not found"})
			invocationCounter.WithLabelValues(pmethod, ppath, "404").Inc()
			return
		}
		err = db1.Error
		if err != nil {
			logrus.Warnf("Error getting user during activation. email=%s err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		if u.Enabled == 0 {
			c.JSON(460, gin.H{"message": "Account disabled"})
			invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
			return
		}

		if u.ActivationDate != nil {
			c.JSON(455, gin.H{"message": "Account already activated"})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return
		}

		err = db.Model(&u).UpdateColumn("activationDate", time.Now()).Error
		if err != nil {
			logrus.Warnf("Error activating user. email=%s err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		//ACCOUNT ACTIVATED. CREATE ACCESS TOKENS FOR DIRECT SIGNIN
		tokensResponse, err := createAccessAndRefreshToken(u.Name, email, opt.accessTokenDefaultScope)
		if err != nil {
			logrus.Warnf("Error generating tokens for user %s. err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		tokensResponse["message"] = "Account activated successfuly"
		c.JSON(202, tokensResponse)
		invocationCounter.WithLabelValues(pmethod, ppath, "202").Inc()
		logrus.Debugf("Account %s activated successfuly", email)
	}
}
