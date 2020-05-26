package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

func (h *HTTPServer) setupPasswordHandlers() {
	h.router.POST("/user/:email/password-reset-request", passwordResetRequest())
	h.router.POST("/user/:email/password-reset-change", passwordResetChange())
	h.router.POST("/user/:email/password-change", passwordChange())
}

func passwordResetRequest() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "POST"
		ppath := "/user/:email/password-reset-request"

		email := strings.ToLower(c.Param("email"))
		logrus.Debugf("passwordResetRequest email=%s", email)

		logrus.Debugf("Sending password reset mail to %s", email)

		var u User
		db1 := db.First(&u, "email = ?", email)
		err := db1.Error
		if err != nil && !db1.RecordNotFound() {
			logrus.Warnf("Error getting user for sending password reset email. email=%s err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		if u.Enabled == 0 || u.ActivationDate == nil || db1.RecordNotFound() {
			logrus.Infof("Password reset mail won't be sent to %s", email)
			c.JSON(202, gin.H{"message": "If user exists, password reset mail will be sent"})
			invocationCounter.WithLabelValues(pmethod, ppath, "202").Inc()
			return
		}

		_, passwordResetTokenString, err := createJWTToken(email, opt.passwordResetTokenExpirationMinutes, "password-reset", "")
		if err != nil {
			logrus.Warnf("Error creating password reset token for email=%s. err=%s", email, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		htmlBody := strings.ReplaceAll(opt.mailResetPasswordHTMLBody, "DISPLAY_NAME", u.Name)
		htmlBody = strings.ReplaceAll(htmlBody, "PASSWORD_RESET_TOKEN", passwordResetTokenString)
		err = sendMail(opt.mailResetPasswordSubject, htmlBody, email, u.Name)
		if err != nil {
			logrus.Warnf("Couldn't send password reset email to %s (%s). err=%s", email, opt.mailActivationSubject, err)
			mailCounter.WithLabelValues("POST", "activation", "500").Inc()
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		mailCounter.WithLabelValues("POST", "activation", "202").Inc()
		logrus.Infof("Password reset mail sent to %s", u.Name)
		// logrus.Debugf("Password reset token for %s=%s", email, passwordResetTokenString)
		if opt.mailTokensTests == "true" {
			logrus.Warnf("ADDING PASSWORD RESET TOKEN TO RESPONSE HEADER. NEVER USE THIS IN PRODUCTION. DISABLE THIS BY REMOVING ENV 'MAIL_TOKENS_FOR_TESTS'")
			c.Header("Test-Token", passwordResetTokenString)
		}
		c.JSON(202, gin.H{"message": "If user exists, password reset mail will be sent"})
		invocationCounter.WithLabelValues(pmethod, ppath, "202").Inc()
	}
}

func passwordResetChange() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "POST"
		ppath := "/user/:email/password-reset-change"

		email := strings.ToLower(c.Param("email"))
		logrus.Debugf("passwordResetChange email=%s", email)

		_, err := loadAndValidateToken(c.Request, "password-reset", email)
		if err != nil {
			c.JSON(450, gin.H{"message": "Invalid password reset token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		m := make(map[string]string)
		data, _ := ioutil.ReadAll(c.Request.Body)
		err = json.Unmarshal(data, &m)
		if err != nil {
			c.JSON(500, gin.H{"message": fmt.Sprintf("Couldn't parse body contents. err=%s", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		validateAndChangePassword(email, m, c, pmethod, ppath)
	}
}

func passwordChange() func(*gin.Context) {
	return func(c *gin.Context) {
		pmethod := "POST"
		ppath := "/user/:email/password-change"

		email := strings.ToLower(c.Param("email"))
		logrus.Debugf("passwordChange email=%s", email)

		_, err := loadAndValidateToken(c.Request, "access", email)
		if err != nil {
			c.JSON(450, gin.H{"message": "Invalid access token"})
			invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
			return
		}

		var u User
		err = db.First(&u, "email = ? AND activation_date IS NOT NULL AND enabled = 1", email).Error
		if err != nil {
			c.JSON(455, gin.H{"message": "Invalid account"})
			invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
			return
		}

		logrus.Debugf("Verifying current password for %s", email)
		m := make(map[string]string)
		data, _ := ioutil.ReadAll(c.Request.Body)
		err = json.Unmarshal(data, &m)
		if err != nil {
			c.JSON(500, gin.H{"message": fmt.Sprintf("Couldn't parse body contents. err=%s", err)})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}

		currentPassword, exists := m["currentPassword"]
		if !exists {
			c.JSON(470, gin.H{"message": "Invalid current password"})
			invocationCounter.WithLabelValues(pmethod, ppath, "470").Inc()
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(currentPassword))
		if err != nil {
			c.JSON(470, gin.H{"message": "Invalid current password"})
			invocationCounter.WithLabelValues(pmethod, ppath, "470").Inc()
			return
		}

		logrus.Debugf("Current password is valid for password change of %s", email)

		validateAndChangePassword(email, m, c, pmethod, ppath)
	}
}

func validateAndChangePassword(email string, bodyContents map[string]string, c *gin.Context, pmethod string, ppath string) {

	logrus.Debugf("Validate password %s", email)
	valid := validateField(bodyContents, "password", opt.passwordValidationRegex)
	if !valid {
		c.JSON(460, gin.H{"message": "Invalid new password"})
		invocationCounter.WithLabelValues(pmethod, ppath, "460").Inc()
		return
	}

	logrus.Debugf("Validate account status %s", email)
	var u User
	db1 := db.First(&u, "email = ? AND activation_date IS NOT NULL AND enabled = 1", email)
	if db1.RecordNotFound() {
		c.JSON(455, gin.H{"message": "Invalid account"})
		invocationCounter.WithLabelValues(pmethod, ppath, "455").Inc()
		return
	}

	if db1.Error != nil {
		logrus.Warnf("Error getting user %s for password change. err=%s", email, db1.Error)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	logrus.Debugf("Save new password for %s", email)

	phash, err := bcrypt.GenerateFromPassword([]byte(bodyContents["password"]), bcrypt.MinCost)
	if err != nil {
		logrus.Warnf("Couldn't hash password for email=%s. err=%s", email, err)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	err = db.Model(&u).Updates(map[string]interface{}{
		"password_date":        time.Now(),
		"password_valid_util":  generatePasswordValidUntil(),
		"password_hash":        phash,
		"wrong_password_count": 0,
		"wrong_password_date":  nil,
	}).Error
	if err != nil {
		logrus.Warnf("Couldn't save new password for email=%s. err=%s", email, err)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	logrus.Infof("Password for %s changed successfully", email)
	c.JSON(200, gin.H{"message": "Password changed successfully"})
	invocationCounter.WithLabelValues(pmethod, ppath, "200").Inc()
}

func resetWrongPasswordCounters(u *User) error {
	return db.Model(&u).Updates(map[string]interface{}{"wrong_password_count": 0, "wrong_password_date": nil}).Error
}

func generatePasswordValidUntil() *time.Time {
	var passwordValidUntil *time.Time
	if opt.passwordExpirationDays > 0 {
		tp := time.Unix(time.Now().Unix()+int64(60*60*24*opt.passwordExpirationDays), 0)
		passwordValidUntil = &tp
	}
	return passwordValidUntil
}
