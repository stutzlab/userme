package main

// * POST /user/:email/request-reset-password
//   * response status
//     * 202 - password reset request accepted (maybe email doesn't exist and email won't be sent, but we don't want to give this clue to abusers ;), so this kind of details can be accessed only on server logs)
//     * 500 - server error

// * POST /user/:email/reset-password
//   * resquest header: Bearer <reset-password-token>
//   * request body json: newPassword
//   * response status
//     * 200 - password changed successfuly
//     * 450 - invalid token
//     * 460 - invalid new password
//     * 500 - server error

// * POST /user/:email/change-password
//   * resquest header: Bearer <access token>
//   * request body json: currentPassword, newPassword
//   * response status:
//     * 200 - password changed successfuly
//     * 450 - wrong current password (this will be used to indicate that the email doesn't exist too)
//     * 460 - invalid new password
//     * 500 - server error

func (h *HTTPServer) setupPasswordHandlers() {
	// h.router.POST("/user/:email/request-reset-password", passwordResetRequest())
	// h.router.POST("/user/:email/reset-password", passwordReset())
	// h.router.POST("/user/:email/change-password", changePassword())
}

// password change
// logrus.Debugf("Reset wrong password counters")
// err1 := db.Model(&u).UpdateColumn("wrong_password_count", 0).Error
// err2 := db.Model(&u).UpdateColumn("wrong_password_date", nil).Error
// if err1 != nil || err2 != nil {
// 	logrus.Warnf("Couldn't zero wrong password count for %s. err1=%s err2=%s", email, err1, err2)
// 	c.JSON(500, gin.H{"message": "Server error"})
// 	invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
// 	return
// }

func resetWrongPasswordCounters(u *User) error {
	err := db.Model(&u).UpdateColumn("wrong_password_count", 0).Error
	if err != nil {
		return err
	}
	err = db.Model(&u).UpdateColumn("wrong_password_date", nil).Error
	if err != nil {
		return err
	}
	return nil
}
