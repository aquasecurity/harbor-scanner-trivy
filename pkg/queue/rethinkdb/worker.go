package rethinkdb

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"

	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

type workerPool struct {
	conn           r.QueryExecutor
	started        bool
	done           chan bool
	scanController scan.Controller
	cfg            etc.Rethink
}

func NewWorkerPool(conn r.QueryExecutor, scanController scan.Controller, rethinkCfg etc.Rethink) queue.Worker {
	return &workerPool{
		conn:           conn,
		scanController: scanController,
		started:        false,
		done:           nil,
		cfg:            rethinkCfg,
	}
}

func (w *workerPool) Start() {
	if w.started {
		logrus.Warnln("Worker pool already started")
		return
	}

	w.done = make(chan bool)
	w.started = true

	jobs, err := r.Table(w.cfg.JobsTable).Changes().Field("new_val").Filter(r.Row.HasFields("assigned_at").Not()).Run(w.conn)
	if err != nil {
		logrus.WithError(err).Fatalln("Could not subscribe to getting new jobs")
	}

	jobsChan := make(chan rethinkdbJob)

	for i := 0; i < w.cfg.JobsConcurrency; i++ {
		go w.jobHandler(jobsChan)
	}

	go func() {
		var job rethinkdbJob
		for jobs.Next(&job) {
			res, err := r.Table(w.cfg.JobsTable).Get(job.ID).Update(map[string]time.Time{"assigned_at": time.Now().UTC()}).RunWrite(w.conn)
			if err != nil {
				logrus.WithError(err).Errorln("Could not update rethinkdb job")
				continue
			}

			// The current node doesn't get the job
			if res.Replaced != 1 {
				continue
			}

			select {
			case <-w.done:
				break
			default:
				jobsChan <- job
			}
		}

		if jobs.Err() != nil {
			logrus.WithError(jobs.Err()).Fatalln("Error occurred while iterating rethinkdb jobs")
		}
	}()

	go func() {
		<-w.done
		close(jobsChan)
		if err = jobs.Close(); err != nil {
			logrus.WithError(err).Fatalln("Could not close rethinkdb jobs subscription")
		}
	}()
}

func (w *workerPool) Stop() {
	if !w.started {
		logrus.Warnln("Worker pool already stopped")
		return
	}

	close(w.done)
	w.started = false
}

// Scan and delete the corresponding job from rethinkdb
func (w *workerPool) jobHandler(jobs <-chan rethinkdbJob) {
	for job := range jobs {
		logrus.WithField("scan_job_id", job.ID).Debug("Executing enqueued scan job")

		// If scanning fails, the job should still be deleted
		if err := w.scanController.Scan(job.ID, job.ScanRequest); err != nil {
			logrus.WithError(err).Errorf("Failed to scan job %v", job.ScanRequest)
		}

		res, err := r.Table(w.cfg.JobsTable).Get(job.ID).Delete().RunWrite(w.conn)
		if err != nil || res.Deleted != 1 {
			logrus.WithError(err).Errorln("Could not delete scanned job from rethinkdb")
		}
	}
}
