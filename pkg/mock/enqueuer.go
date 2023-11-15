package mock

import (
	"context"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/stretchr/testify/mock"
)

type Enqueuer struct {
	mock.Mock
}

func NewEnqueuer() *Enqueuer {
	return &Enqueuer{}
}

func (em *Enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (job.ScanJob, error) {
	args := em.Called(ctx, request)
	return args.Get(0).(job.ScanJob), args.Error(1)
}
