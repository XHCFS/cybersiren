package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login verifies an email/password against users.password_hash (bcrypt) and
// issues a JWT carrying the user's id + org. Invalid credentials return 401
// without revealing whether the email or the password was wrong.
func (s *Server) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password required"})
		return
	}

	u, err := s.q.GetUserForLogin(c.Request.Context(), req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !u.PasswordHash.Valid ||
		bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := s.authn.IssueJWT(u.ID, u.OrgID, 0)
	if err != nil {
		s.fail(c, "issue token failed", err)
		return
	}
	_ = s.q.TouchUserLastLogin(c.Request.Context(), u.ID)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  gin.H{"id": u.ID, "email": u.Email, "role": u.Role, "org_id": u.OrgID},
	})
}
