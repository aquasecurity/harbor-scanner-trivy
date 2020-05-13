package etc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/sirupsen/logrus"
	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

const (
	id            = "id"
	lastUpdatedAt = "last_updated_at"
)

func GetRethinkdbConnection(config Rethink) (*r.Session, error) {
	connectOpts, err := getConnectionOpts(config)
	if err != nil {
		return nil, fmt.Errorf("getting connection options failed: %w", err)
	}

	db, err := r.Connect(connectOpts)
	if err != nil {
		return nil, fmt.Errorf("connecting to rethinkdb failed: %w", err)
	}

	r.SetTags("rethinkdb", "json")

	if err = createDatabaseIfNotExist(config.Database, db); err != nil {
		return nil, fmt.Errorf("creating database %s failed: %w", config.Database, err)
	}

	if err = createTableIfNotExist(config.ScansTable, id, db); err != nil {
		return nil, fmt.Errorf("creating table %s failed: %w", config.ScansTable, err)
	}

	if err = createTableIfNotExist(config.JobsTable, id, db); err != nil {
		return nil, fmt.Errorf("creating table %s failed: %w", config.JobsTable, err)
	}

	if err = createIndicesIfNotExist(config.ScansTable, []string{lastUpdatedAt}, db); err != nil {
		return nil, fmt.Errorf("creating indices on table %s failed: %w", config.ScansTable, err)
	}

	go deleteOldRecordsPeriodically(config.ScansTable, lastUpdatedAt, config.ScansTTL, db)

	return db, nil
}

func getConnectionOpts(config Rethink) (r.ConnectOpts, error) {
	connectOpts := r.ConnectOpts{
		Addresses:  config.Addresses,
		Database:   config.Database,
		MaxOpen:    config.MaxOpen,
		InitialCap: config.InitialCap,
	}

	if config.RootCA != "" {
		caCert, err := ioutil.ReadFile(config.RootCA)
		if err != nil {
			return r.ConnectOpts{}, fmt.Errorf("cannot read root CA: %w", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		connectOpts.TLSConfig = &tls.Config{
			RootCAs: caCertPool,
			MinVersion: tls.VersionTLS12,
		}
	}

	if config.ClientTLSCertificate != "" && config.ClientTLSKey != "" {
		clientCert, err := tls.LoadX509KeyPair(config.ClientTLSCertificate, config.ClientTLSKey)
		if err != nil {
			return r.ConnectOpts{}, fmt.Errorf("cannot read client certificate or key: %w", err)
		}

		if connectOpts.TLSConfig == nil {
			connectOpts.TLSConfig = new(tls.Config)
		}

		connectOpts.TLSConfig.Certificates = []tls.Certificate{clientCert}
	}

	return connectOpts, nil
}

func createDatabaseIfNotExist(database string, db *r.Session) error {
	var dbExists bool

	if err := r.DBList().Contains(database).ReadOne(&dbExists, db); err != nil {
		return fmt.Errorf("could not determine whether db %s exists: %w", database, err)
	}

	if !dbExists {
		res, err := r.DBCreate(database).RunWrite(db)
		if err != nil || res.DBsCreated != 1 {
			return fmt.Errorf("creating db %s failed: %w", database, err)
		}
	}

	return nil
}

func createTableIfNotExist(table, primaryKey string, db *r.Session) error {
	var tableExists bool

	if err := r.TableList().Contains(table).ReadOne(&tableExists, db); err != nil {
		return fmt.Errorf("could not determine whether table %s exists: %w", table, err)
	}

	if !tableExists {
		res, err := r.TableCreate(table, r.TableCreateOpts{PrimaryKey: primaryKey}).RunWrite(db)
		if err != nil || res.TablesCreated != 1 {
			return fmt.Errorf("creating table %s failed: %w", table, err)
		}
	}

	return nil
}

func createIndicesIfNotExist(table string, indices []string, db *r.Session) error {
	contains := func(key string, keys []string) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}

		return false
	}

	existingIndices := make([]string, 0)

	if err := r.Table(table).IndexList().ReadAll(&existingIndices, db); err != nil {
		return fmt.Errorf("could not get existing indices for table %s: %w", table, err)
	}

	for _, index := range indices {
		if !contains(index, existingIndices) {
			res, err := r.Table(table).IndexCreate(index).RunWrite(db)
			if err != nil || res.Created != 1 {
				return fmt.Errorf("creating index %s on table %s failed: %w", index, table, err)
			}
		}
	}

	return nil
}

func deleteOldRecordsPeriodically(table, dateIndex string, ttl time.Duration, db *r.Session) {
	ticker := time.NewTicker(ttl / 10)

	for range ticker.C {
		res, err := r.Table(table).Between(r.MinVal, time.Now().UTC().Add(-ttl), r.BetweenOpts{Index: dateIndex}).Delete().RunWrite(db)
		if err != nil {
			logrus.WithError(err).WithField("table", table).Warnln("Error deleting old entries from table")
		} else {
			logrus.WithField("table", table).Debugf("Successfully deleted %d old records from table", res.Deleted)
		}
	}
}
