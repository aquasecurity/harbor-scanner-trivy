package redisx

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/stretchr/testify/assert"
)

func TestGetPool(t *testing.T) {

	t.Run("Should return error when configured to connect to secure redis", func(t *testing.T) {
		_, err := NewPool(etc.RedisPool{
			URL: "rediss://hostname:6379",
		})
		assert.EqualError(t, err, "invalid redis URL scheme: rediss")
	})

	t.Run("Should return error when configured with unsupported url scheme", func(t *testing.T) {
		_, err := NewPool(etc.RedisPool{
			URL: "https://hostname:6379",
		})
		assert.EqualError(t, err, "invalid redis URL scheme: https")
	})

}

func TestParseSentinelURL(t *testing.T) {
	testCases := []struct {
		configURL           string
		expectedSentinelURL SentinelURL
		expectedError       string
	}{
		{
			configURL: "redis+sentinel://harbor:s3cret@somehost:26379,otherhost:26479/mymaster/3",
			expectedSentinelURL: SentinelURL{
				Password: "s3cret",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    3,
			},
		},
		{
			configURL: "redis+sentinel://:s3cret@somehost:26379,otherhost:26479/mymaster/5",
			expectedSentinelURL: SentinelURL{
				Password: "s3cret",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    5,
			},
		},
		{
			configURL: "redis+sentinel://:s3cret@somehost:26379,otherhost:26479/mymaster",
			expectedSentinelURL: SentinelURL{
				Password: "s3cret",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    0,
			},
		},
		{
			configURL:     "redis+sentinel://:s3cret@somehost:26379,otherhost:26479/mymaster/X",
			expectedError: "invalid redis sentinel URL: invalid database number: X",
		},
		{
			configURL:     "redis+sentinel://:s3cret@somehost:26379,otherhost:26479",
			expectedError: "invalid redis sentinel URL: no master name",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.configURL, func(t *testing.T) {
			configURL, err := url.Parse(tc.configURL)
			require.NoError(t, err)

			sentinelURL, err := ParseSentinelURL(configURL)

			switch {
			case tc.expectedError == "":
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSentinelURL, sentinelURL)
			default:
				assert.EqualError(t, err, tc.expectedError)
			}
		})
	}

}
