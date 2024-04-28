//go:build linux

package aws_secretsmanager

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/component"
	"github.com/stretchr/testify/require"
)

func Test_Convert(t *testing.T) {
	o := component.Options{
		ID:            "t1",
		OnStateChange: func(_ component.Exports) {},
		Registerer:    prometheus.NewRegistry(),
	}
	s3File, err := New(o,
		Arguments{
			SecretName: "/alloy/test",
		})
	require.NoError(t, err)
	require.NotNil(t, s3File)
}
