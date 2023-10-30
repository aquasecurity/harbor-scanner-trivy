package mock

import (
	"context"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/stretchr/testify/mock"
)

type Store struct {
	mock.Mock
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Create(ctx context.Context, scanJob job.ScanJob) error {
	args := s.Called(ctx, scanJob)
	return args.Error(0)
}

func (s *Store) Get(ctx context.Context, scanJobID string) (*job.ScanJob, error) {
	args := s.Called(ctx, scanJobID)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (s *Store) UpdateStatus(ctx context.Context, scanJobID string, newStatus job.ScanJobStatus, error ...string) error {
	args := s.Called(ctx, scanJobID, newStatus, error)
	return args.Error(0)
}

func (s *Store) UpdateReport(ctx context.Context, scanJobID string, report harbor.ScanReport) error {
	args := s.Called(ctx, scanJobID, report)
	return args.Error(0)
}
