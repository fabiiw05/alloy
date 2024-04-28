package aws_secretsmanager

import (
	"fmt"
	"time"

	"github.com/grafana/alloy/syntax/alloytypes"
)

// Arguments implements the input for the aws_secretsmanager component.
type Arguments struct {
	SecretName   string `alloy:"secretname,attr"`
	VersionStage string `alloy:"secretversion,attr,optional"`
	// PollFrequency determines the frequency to check for changes
	// defaults to 10m.
	PollFrequency time.Duration `alloy:"poll_frequency,attr,optional"`

	// Options allows the overriding of default settings.
	Options Client `alloy:"client,block,optional"`
}

// Client implements specific AWS configuration options
type Client struct {
	AccessKey     string            `alloy:"key,attr,optional"`
	Secret        alloytypes.Secret `alloy:"secret,attr,optional"`
	Endpoint      string            `alloy:"endpoint,attr,optional"`
	DisableSSL    bool              `alloy:"disable_ssl,attr,optional"`
	UsePathStyle  bool              `alloy:"use_path_style,attr,optional"`
	Region        string            `alloy:"region,attr,optional"`
	SigningRegion string            `alloy:"signing_region,attr,optional"`
}

const minimumPollFrequency = 30 * time.Second

// DefaultArguments sets the poll frequency
var DefaultArguments = Arguments{
	PollFrequency: 10 * time.Minute,
	VersionStage:  "AWSCURRENT",
}

// SetToDefault implements syntax.Defaulter.
func (a *Arguments) SetToDefault() {
	*a = DefaultArguments
}

// Validate implements syntax.Validator.
func (a *Arguments) Validate() error {
	if a.PollFrequency <= minimumPollFrequency {
		return fmt.Errorf("poll_frequency must be greater than 30s")
	}
	return nil
}

// Exports implements the file content
type Exports struct {
	Data map[string]alloytypes.Secret `alloy:"data,attr"`
}
