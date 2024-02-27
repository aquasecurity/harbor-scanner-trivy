package mock

import (
	"context"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/stretchr/testify/mock"
)

type Enqueuer struct {
	mock.Mock
}

func NewEnqueuer() *Enqueuer {
	return &Enqueuer{}
}

func (em *Enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	args := em.Called(ctx, request)
	return args.String(0), args.Error(1)
}
