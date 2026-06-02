package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
)

// ListEmails returns a paged, org-scoped scan list with verdict + score.
func (s *Server) ListEmails(c *gin.Context) {
	limit, offset := paging(c)
	rows, err := s.q.ListEmailsByOrg(c.Request.Context(), dbsqlc.ListEmailsByOrgParams{
		OrgID: orgParam(c), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.fail(c, "emails query failed", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"emails": rows, "page_size": limit})
}

// GetEmail returns the full detail for one email (org-scoped): header fields
// plus URLs, attachments, recipients, and verdict history.
func (s *Server) GetEmail(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email id"})
		return
	}
	ctx := c.Request.Context()

	email, err := s.q.GetEmailForOrg(ctx, dbsqlc.GetEmailForOrgParams{InternalID: id, OrgID: orgParam(c)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "email not found"})
			return
		}
		s.fail(c, "email detail query failed", err)
		return
	}

	urls, err := s.q.ListEmailURLsForDetail(ctx, id)
	if err != nil {
		s.fail(c, "email urls query failed", err)
		return
	}
	attachments, err := s.q.ListEmailAttachmentsForDetail(ctx, id)
	if err != nil {
		s.fail(c, "email attachments query failed", err)
		return
	}
	recipients, err := s.q.ListEmailRecipientsForDetail(ctx, id)
	if err != nil {
		s.fail(c, "email recipients query failed", err)
		return
	}
	verdicts, err := s.q.ListEmailVerdicts(ctx, id)
	if err != nil {
		s.fail(c, "email verdicts query failed", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"email":       email,
		"urls":        urls,
		"attachments": attachments,
		"recipients":  recipients,
		"verdicts":    verdicts,
	})
}
