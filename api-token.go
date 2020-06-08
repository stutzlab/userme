package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
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

		googleToken, exists := m["googleToken"]
		if exists {
			processGoogleLogin(m, googleToken, c, pmethod, ppath)
			return
		}

		processLocalPasswordLogin(m, c, pmethod, ppath)
	}
}

func processGoogleLogin(m map[string]string, googleToken string, c *gin.Context, pmethod string, ppath string) {
	logrus.Debugf("Authentication using Google login")

	if opt.googleClientID == "" || opt.googleClientSecret == "" {
		c.JSON(400, gin.H{"message": "Google login disabled"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}
	logrus.Errorf("Google login not implemented yet")
	return
}

func processFacebookLogin(m map[string]string, shortLivedFacebookToken string, c *gin.Context, pmethod string, ppath string) {
	logrus.Debugf("Authentication using Facebook login")

	if opt.facebookClientID == "" || opt.facebookClientSecret == "" {
		c.JSON(400, gin.H{"message": "Facebook login disabled"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	logrus.Debugf("Exchanging short lived FB token by a long lived one")
	furl := fmt.Sprintf("https://graph.facebook.com/v7.0/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s", opt.facebookClientID, opt.facebookClientSecret, shortLivedFacebookToken)
	response, err := http.Get(furl)
	if err != nil {
		logrus.Warnf("Error calling Facebook to get a long lived token. %s", err)
		c.JSON(500, gin.H{"message": "Error calling Facebook API"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}
	if response.StatusCode != 200 {
		logrus.Warnf("Couldn't get long lived token at Facebook. status=%s", response.Status)
		rb, _ := ioutil.ReadAll(response.Body)
		logrus.Debugf("FB: %s", string(rb))
		c.JSON(400, gin.H{"message": "Couldn't get long lived token at Facebook"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	rm := make(map[string]interface{})
	data, _ := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(data, &rm)
	if err != nil {
		logrus.Debugf("Couldn't parse FB body contents for long lived token request. body=%s err=%s", string(data), err)
		c.JSON(500, gin.H{"message": "Couldn't parse FB body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}
	facebookToken0, exists := rm["access_token"]
	if !exists {
		logrus.Debugf("FB body contents for long lived token don't contain 'access_token'. body=%s", err)
		c.JSON(500, gin.H{"message": "Couldn't parse FB body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}
	facebookToken := facebookToken0.(string)

	logrus.Debugf("Checking facebook token validity")
	token, success := processFacebookToken(c, facebookToken, pmethod, ppath)
	if !success {
		return
	}
	logrus.Debugf("Facebook token valid for %s. Checking if account already exists")

	tname0, exists := token["name"]
	if !exists {
		c.JSON(400, gin.H{"message": "Couldn't get 'name' from Facebook token"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}
	tname := tname0

	temail, exists := token["email"]
	if !exists {
		c.JSON(400, gin.H{"message": fmt.Sprintf("Couldn't get email from Facebook token for user %s", tname)})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	u := User{}
	if db.First(&u, "email = ?", temail).RecordNotFound() {
		logrus.Debugf("User %s not found. Auto creating user for Facebook login", temail)
		t := time.Now()
		u.ActivationDate = &t
		u = User{
			Name:           tname,
			Email:          temail,
			Enabled:        1,
			CreationDate:   time.Now(),
			ActivationDate: &t,
		}
		err := db.Create(&u).Error
		if err != nil {
			logrus.Warnf("Error creating user email=%s for Facebook login. err=%s", temail, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return
		}
		logrus.Debugf("New account created from Facebook login. email=%s", temail)

	}

	m["email"] = temail

	_, success = processUserActivated(m, c, pmethod, ppath)
	if !success {
		return
	}

	validateUserAndOutputTokensToResponse(&u, c, pmethod, ppath, "facebook", facebookToken)
	logrus.Debugf("Facebook login for %s", u.Email)
}

func processLocalPasswordLogin(m map[string]string, c *gin.Context, pmethod string, ppath string) {
	logrus.Debugf("Authentication using local password")

	u, success := processUserActivated(m, c, pmethod, ppath)
	if !success {
		return
	}
	email := u.Email

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
		err = db.Model(&u).UpdateColumn("wrong_password_count", u.WrongPasswordCount+1).Error
		if err != nil {
			logrus.Warnf("Couldn't increment wrong password count for %s. err=%s", email, err)
		}
		err = db.Model(&u).UpdateColumn("wrong_password_date", time.Now()).Error
		if err != nil {
			logrus.Warnf("Couldn't update wrong password date for %s. err=%s", email, err)
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

func processUserActivated(m map[string]string, c *gin.Context, pmethod string, ppath string) (*User, bool) {
	email, exists := m["email"]
	if !exists {
		c.JSON(400, gin.H{"message": "Couldn't get email/password from body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return nil, false
	}

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

func validateUserAndOutputTokensToResponse(u *User, c *gin.Context, pmethod string, ppath string, authType string, socialToken string) {
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

	} else if authType == "facebook" {
		customRefreshTokenClaims["facebookToken"] = socialToken
	}

	logrus.Debugf("User %s authenticated and validated", u.Email)

	tokensResponse, err := createAccessAndRefreshToken(u.Name, u.Email, authType, customAccessTokenClaims, customRefreshTokenClaims)
	if err != nil {
		logrus.Warnf("Error generating tokens for user %s. err=%s", u.Email, err)
		c.JSON(500, gin.H{"message": "Server error"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}

	c.JSON(200, tokensResponse)
	invocationCounter.WithLabelValues(pmethod, ppath, "200").Inc()
	logrus.Debugf("Tokens for %s generated and sent to response", u.Name)
}

func processFacebookToken(c *gin.Context, facebookToken string, pmethod string, ppath string) (map[string]string, bool) {
	// logrus.Debugf("FB token=%s", facebookToken)
	furl := fmt.Sprintf("https://graph.facebook.com/me?fields=email,name&access_token=%s", facebookToken)
	response, err := http.Get(furl)
	if err != nil {
		logrus.Warnf("Error calling Facebook to validate token. %s", err)
		c.JSON(500, gin.H{"message": "Error calling Facebook to validate token"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return nil, false
	}
	if response.StatusCode != 200 {
		logrus.Warnf("Facebook didn't validate token. status=%s", response.Status)
		rb, _ := ioutil.ReadAll(response.Body)
		logrus.Debugf("FB: %s", string(rb))
		c.JSON(400, gin.H{"message": "Token could not be validated at Facebook"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return nil, false
	}

	token := make(map[string]string)
	data, _ := ioutil.ReadAll(response.Body)
	err2 := json.Unmarshal(data, &token)
	if err2 != nil {
		c.JSON(500, gin.H{"message": "Token could not be read from Facebook"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return nil, false
	}

	//FB bug: https://stackoverflow.com/questions/13510458/golang-convert-iso8859-1-to-utf8
	token["email"] = toUtf8(token["email"])
	// logrus.Debugf("FB token=%v", token)

	return token, true
}

func toUtf8(iso88591str string) string {
	iso88591buf := []byte(iso88591str)
	buf := make([]rune, len(iso88591buf))
	for i, b := range iso88591buf {
		buf[i] = rune(b)
	}
	return string(buf)
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

		if authType == "facebook" {
			facebookToken0, exists := claims["facebookToken"]
			if !exists {
				logrus.Warnf("Refresh token valid but doesn't have 'facebookToken' claim")
				c.JSON(450, gin.H{"message": "Invalid refresh token"})
				invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
				return
			}
			facebookToken := facebookToken0.(string)

			token, ok := processFacebookToken(c, facebookToken, pmethod, ppath)
			if !ok {
				return
			}
			logrus.Debugf("FB TOKEN=%v", token)

			temail, _ := token["email"]
			if email != temail {
				logrus.Warnf("Refresh token valid but 'facebookToken' is for another email. %s!=%s", temail, email)
				c.JSON(450, gin.H{"message": "Invalid refresh token"})
				invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
				return
			}

			socialToken = facebookToken
		}

		if authType == "google" {
			googleToken0, exists := claims["googleToken"]
			if !exists {
				logrus.Warnf("Refresh token valid but doesn't have 'googleToken' claim")
				c.JSON(450, gin.H{"message": "Invalid refresh token"})
				invocationCounter.WithLabelValues(pmethod, ppath, "450").Inc()
				return
			}
			googleToken := googleToken0.(string)
			socialToken = googleToken
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
