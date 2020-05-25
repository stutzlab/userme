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
