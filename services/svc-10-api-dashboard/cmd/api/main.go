// svc-10-api-dashboard is the read-mostly analyst-console BACKEND (MVP-7). It is
// HTTP-ONLY: a JWT login + a persisted read API over the email/verdict/rule
// tables, the 5 materialized-view stats dashboards, a read-only rules list, and
// a scan-submission proxy to svc-01. There is NO Kafka consumer and NO WebSocket
// feed — P6.2 (the emails.verdict live feed) is DROPPED for the MVP, so the old
// consumer + ring buffer are gone.
//
// Every read against an RLS-forced table runs inside a tenant-scoped transaction
// keyed by the authenticated JWT claim OrgID (G10). MVP-1 freezes a single org.
package main

import (
	"os"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/shared/svckit"

	apidashboard "github.com/saif/cybersiren/services/svc-10-api-dashboard/internal"
)

const serviceName = "svc-10-api-dashboard"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:       serviceName,
		NeedsDB:    true,
		HTTPPort:   8088,
		HTTPRoutes: apidashboard.RegisterRoutes,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
