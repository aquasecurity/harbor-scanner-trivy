package mock

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
	"github.com/stretchr/testify/mock"
)

type Store struct {
	mock.Mock
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) SaveScanJob(scanJob job.ScanJob) error {
	args := s.Called(scanJob)
	return args.Error(0)
}

func (s *Store) GetScanJob(scanJobID string) (*job.ScanJob, error) {
	args := s.Called(scanJobID)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (s *Store) UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error {
	args := s.Called(scanJobID, newStatus, error)
	return args.Error(0)
}

func (s *Store) UpdateReport(scanJobID string, report harbor.ScanReport) error {
	args := s.Called(scanJobID, report)
	return args.Error(0)
}
