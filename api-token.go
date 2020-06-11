package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"strings"
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

//TOKEN CREATION
func tokenCreate() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := c.Request.Method
		ppath := c.FullPath()

		m := make(map[string]string)
		data, _ := ioutil.ReadAll(c.Request.Body)
		err := json.Unmarshal(data, &m)
		if err != nil {
			c.JSON(400, gin.H{"message": fmt.Sprintf("Couldn't parse body contents. err=%s", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
			return
		}

		facebookToken, exists := m["facebookToken"]
		if exists {
			processFacebookLogin(m, facebookToken, c, pmethod, ppath)
			return
		}

		googleAuthCode, exists := m["googleAuthCode"]
		if exists {
			processGoogleLogin(m, googleAuthCode, c, pmethod, ppath)
			return
		}

		processLocalPasswordLogin(m, c, pmethod, ppath)
	}
}

func processLocalPasswordLogin(m map[string]string, c *gin.Context, pmethod string, ppath string) {
	logrus.Debugf("Authentication using local password")

	email, exists := m["email"]
	if !exists {
		c.JSON(400, gin.H{"message": "Couldn't get email/password from body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	u, success := processValidateUserActivated(email, c, pmethod, ppath)
	if !success {
		return
	}
	email = u.Email

	password, exists := m["password"]
	if !exists {
		c.JSON(400, gin.H{"message": "Couldn't get email/password from body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}
	logrus.Debugf("Verify wrong password retries")
	if u.WrongPasswordDate != nil {
		if int(u.WrongPasswordCount) >= opt.passwordRetriesMax {
			logrus.Infof("Max wrong password retries reached for %s. Account locked", email)
			c.JSON(465, gin.H{"message": "Max wrong password retries reached. Reset your password"})
			invocationCounter.WithLabelValues(pmethod, ppath, "465").Inc()
			return
		}
		delaySeconds := opt.passwordRetriesTimeSeconds * int(math.Pow(2, float64(u.WrongPasswordCount)))
		if time.Now().Before(u.WrongPasswordDate.Add(time.Duration(delaySeconds) * time.Second)) {
			logrus.Infof("Password retry time delay enforced for %s. delay=%d", email, delaySeconds)
			c.JSON(450, gin.H{"message": "Email/password not valid"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}
	}

	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	if err != nil {
		logrus.Infof("Invalid password for %s", email)

		logrus.Debugf("Increment wrong password counters")
		err = db.Model(&u).UpdateColumn("wrong_password_count", u.WrongPasswordCount+1, "wrong_password_date", time.Now()).Error
		if err != nil {
			logrus.Warnf("Couldn't increment wrong password count for %s. err=%s", email, err)
		}

		c.JSON(450, gin.H{"message": "Email/password not valid"})
		invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
		return
	}

	logrus.Debugf("Reset wrong password counters")
	err = resetWrongPasswordCounters(u)
	if err != nil {
		logrus.Warnf("Couldn't zero wrong password count for %s. err=%s", email, err)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	validateUserAndOutputTokensToResponse(u, c, pmethod, ppath, "password", "")
	logrus.Debugf("Local password login for %s", email)
}

func processValidateUserActivated(email string, c *gin.Context, pmethod string, ppath string) (*User, bool) {
	var u User
	db1 := db.First(&u, "email = ? AND activation_date IS NOT NULL", email)

	if db1.RecordNotFound() {
		c.JSON(450, gin.H{"message": "Email/password not valid"})
		invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
		return nil, false
	}

	if db1.Error != nil {
		logrus.Warnf("Error authenticating user %s. err=%s", email, db1.Error)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return nil, false
	}

	return &u, true
}

func validateUserAndOutputTokensToResponse(u *User, c *gin.Context, pmethod string, ppath string, authType string, socialRefreshToken string) {
	if u.Enabled == 0 {
		c.JSON(460, gin.H{"message": "Account disabled"})
		invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
		return
	}

	customAccessTokenClaims := make(map[string]interface{})
	customAccessTokenClaims["scope"] = strings.Split(opt.accessTokenDefaultScope, ",")

	customRefreshTokenClaims := make(map[string]interface{})

	if authType == "password" {
		if u.PasswordValidUntil != nil {
			if u.PasswordValidUntil.Before(time.Now()) {
				c.JSON(455, gin.H{"message": "Password expired"})
				invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
				return
			}
		}

	}

	if socialRefreshToken != "" {
		customRefreshTokenClaims["socialToken"] = socialRefreshToken
	}

	logrus.Debugf("User %s authenticated and validated", u.Email)

	tokensResponse, err := createAccessAndRefreshToken(u.Name, u.Email, authType, customAccessTokenClaims, customRefreshTokenClaims)
	if err != nil {
		logrus.Warnf("Error generating tokens for user %s. err=%s", u.Email, err)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	err = db.Model(&u).UpdateColumn("last_token_type", authType, "last_token_date", time.Now()).Error
	if err != nil {
		logrus.Warnf("Couldn't update last_token_type/date for %s. err=%s", u.Email, err)
	}

	c.JSON(200, tokensResponse)
	invocationCounter.WithLabelValues(pmethod, ppath, "200").Inc()
	logrus.Debugf("Tokens for %s generated and sent to response", u.Name)
}

//TOKEN REFRESH
func tokenRefresh() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := c.Request.Method
		ppath := c.FullPath()

		claims, err := loadAndValidateToken(c.Request, "refresh", "")
		if err != nil {
			c.JSON(450, gin.H{"message": "Invalid refresh token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		email0, exists := claims["sub"]
		if !exists {
			logrus.Warnf("Refresh token valid but doesn't have 'sub' claim")
			c.JSON(450, gin.H{"message": "Invalid refresh token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}
		email := email0.(string)

		authType0, exists := claims["authType"]
		if !exists {
			logrus.Warnf("Refresh token valid but doesn't have 'authType' claim")
			c.JSON(450, gin.H{"message": "Invalid refresh token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}
		authType := authType0.(string)

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

		socialToken := ""

		if authType != "password" {
			socialToken0, exists := claims["socialToken"]
			if !exists {
				logrus.Warnf("Refresh token valid but doesn't have 'socialToken' claim")
				c.JSON(450, gin.H{"message": "Invalid refresh token"})
				invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
				return
			}
			socialToken = socialToken0.(string)

			if authType == "facebook" {
				temail, _, success := processFacebookToken(c, socialToken, pmethod, ppath)
				if !success {
					return
				}

				socialToken1, success := processFacebookRefreshToken(c, socialToken, pmethod, ppath)
				if !success {
					return
				}
				socialToken = socialToken1

				if email != temail {
					logrus.Warnf("Refresh token valid but 'socialToken' is for another email. %s!=%s", temail, email)
					c.JSON(450, gin.H{"message": "Invalid refresh token"})
					invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
					return
				}

			} else if authType == "google" {
				temail, _, success := processGoogleRefreshToken(c, socialToken, pmethod, ppath)
				if !success {
					return
				}

				if email != temail {
					logrus.Warnf("Refresh token valid but 'socialToken' is for another email. %s!=%s", temail, email)
					c.JSON(450, gin.H{"message": "Invalid refresh token"})
					invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
					return
				}

				logrus.Debugf("Google refresh token valid for %s. Checking if account already exists")
			}
		}

		validateUserAndOutputTokensToResponse(&u, c, pmethod, ppath, authType, socialToken)
		logrus.Debugf("Token refresh for %s", email)
	}
}

//TOKEN INFO
func tokenInfo() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := c.Request.Method
		ppath := c.FullPath()

		claims, err := loadAndValidateToken(c.Request, "", "")
		if err != nil {
			logrus.Debugf("Invalid token. err=%s", err)
			c.JSON(450, gin.H{"message": "Invalid token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		email, exists := claims["sub"]
		if !exists {
			logrus.Debugf("Invalid token. 'sub' claim not found")
			c.JSON(450, gin.H{"message": "Invalid token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		var u User
		db1 := db.First(&u, "email = ? AND enabled = 1", email)

		if db1.RecordNotFound() {
			c.JSON(455, gin.H{"message": "User not enabled"})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return

		}

		typ, exists1 := claims["typ"]
		if !exists1 {
			logrus.Debugf("Invalid token. 'typ' claim not found")
			c.JSON(450, gin.H{"message": "Invalid token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}
		if (typ == "access" || typ == "refresh") && u.ActivationDate == nil {
			c.JSON(460, gin.H{"message": "Account not activated"})
			invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
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
