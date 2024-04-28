package aws_secretsmanager

import (
	"context"
	"crypto/tls"

	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-kit/log"

	"github.com/grafana/alloy/internal/alloy/logging/level"
	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/syntax/alloytypes"
)

func init() {
	component.Register(component.Registration{
		Name:      "remote.aws_secretsmanager",
		Stability: featuregate.StabilityGenerallyAvailable,
		Args:      Arguments{},
		Exports:   Exports{},
		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

type Component struct {
	mut     sync.Mutex
	opts    component.Options
	log     log.Logger
	args    Arguments
	health  component.Health
	content map[string]interface{}

	watcher    *watcher
	updateChan chan result
}

var (
	_ component.Component       = (*Component)(nil)
	_ component.HealthComponent = (*Component)(nil)
)

// New initializes the aws_secretsmanager component.
func New(o component.Options, args Arguments) (*Component, error) {
	awscfg, err := generateAWSConfig(args)
	if err != nil {
		return nil, err
	}

	secretsmanagerClient := secretsmanager.NewFromConfig(*awscfg)

	s := &Component{
		opts:       o,
		args:       args,
		health:     component.Health{},
		updateChan: make(chan result),
	}

	w := newWatcher(args.SecretName, args.VersionStage, s.updateChan, args.PollFrequency, secretsmanagerClient)
	s.watcher = w

	content, err := w.updateSecret()
	s.handleContentPolling(content, err)
	return s, nil
}

// Run activates the content handler and watcher.
func (s *Component) Run(ctx context.Context) error {
	go s.handleContentUpdate(ctx)
	go s.watcher.run(ctx)
	<-ctx.Done()

	return nil
}

// Update is called whenever the arguments have changed.
func (s *Component) Update(args component.Arguments) error {
	newArgs := args.(Arguments)

	awscfg, err := generateAWSConfig(newArgs)
	if err != nil {
		return nil
	}
	secretsmanagerClient := secretsmanager.NewFromConfig(*awscfg)

	s.mut.Lock()
	defer s.mut.Unlock()
	s.args = newArgs
	s.watcher.updateValues(newArgs.SecretName, newArgs.VersionStage, newArgs.PollFrequency, secretsmanagerClient)

	return nil
}

// CurrentHealth returns the health of the component.
func (s *Component) CurrentHealth() component.Health {
	s.mut.Lock()
	defer s.mut.Unlock()
	return s.health
}

func generateAWSConfig(args Arguments) (*aws.Config, error) {
	configOptions := make([]func(*aws_config.LoadOptions) error, 0)
	// Override the endpoint.
	if args.Options.Endpoint != "" {
		endFunc := aws.EndpointResolverWithOptionsFunc(func(service, region string, _ ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{URL: args.Options.Endpoint, SigningRegion: args.Options.SigningRegion}, nil
		})
		endResolver := aws_config.WithEndpointResolverWithOptions(endFunc)
		configOptions = append(configOptions, endResolver)
	}

	// This incredibly nested option turns off SSL.
	if args.Options.DisableSSL {
		httpOverride := aws_config.WithHTTPClient(
			&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: args.Options.DisableSSL,
					},
				},
			},
		)
		configOptions = append(configOptions, httpOverride)
	}

	// Check to see if we need to override the credentials, else it will use the default ones.
	// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
	if args.Options.AccessKey != "" {
		if args.Options.Secret == "" {
			return nil, fmt.Errorf("if accesskey or secret are specified then the other must also be specified")
		}
		credFunc := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     args.Options.AccessKey,
				SecretAccessKey: string(args.Options.Secret),
			}, nil
		})
		credProvider := aws_config.WithCredentialsProvider(credFunc)
		configOptions = append(configOptions, credProvider)
	}

	cfg, err := aws_config.LoadDefaultConfig(context.TODO(), configOptions...)
	if err != nil {
		return nil, err
	}
	// Set region.
	if args.Options.Region != "" {
		cfg.Region = args.Options.Region
	}

	return &cfg, nil
}

// handleContentUpdate reads from the update and error channels setting as appropriate
func (s *Component) handleContentUpdate(ctx context.Context) {
	for {
		select {
		case r := <-s.updateChan:
			// r.result will never be nil,
			s.handleContentPolling(r.result, r.err)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Component) handleContentPolling(newContent map[string]interface{}, err error) {
	s.mut.Lock()
	defer s.mut.Unlock()

	if err == nil {
		newExports := Exports{
			Data: make(map[string]alloytypes.Secret),
		}
		for key, value := range newContent {
			switch value := value.(type) {
			case string:
				newExports.Data[key] = alloytypes.Secret(value)
			case []byte:
				newExports.Data[key] = alloytypes.Secret(value)

			default:
				// Non-string secrets are ignored.
				level.Warn(s.log).Log(
					"msg", "found field in secret which cannot be converted into a string",
					"key", key,
					"type", fmt.Sprintf("%T", value),
				)
			}
		}

		s.opts.OnStateChange(newExports)

		s.content = newContent
		s.health.Health = component.HealthTypeHealthy
		s.health.Message = "Secrets retrieved"
	} else {
		s.health.Health = component.HealthTypeUnhealthy
		s.health.Message = err.Error()
	}
	s.health.UpdateTime = time.Now()
}
