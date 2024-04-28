package aws_secretsmanager

import (
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"context"

	"encoding/json"
)

type watcher struct {
	secretname   string
	versionstage string

	mut      sync.Mutex
	output   chan result
	dlTicker *time.Ticker
	client   *secretsmanager.Client
}

type result struct {
	result map[string]interface{}
	err    error
}

func newWatcher(
	secretname, versionstage string,
	out chan result,
	frequency time.Duration,
	client *secretsmanager.Client,
) *watcher {

	return &watcher{
		secretname:   secretname,
		versionstage: versionstage,
		output:       out,
		dlTicker:     time.NewTicker(frequency),
		client:       client,
	}
}

func (w *watcher) updateValues(secretname string, versionstage string, frequency time.Duration, client *secretsmanager.Client) {
	w.mut.Lock()
	defer w.mut.Unlock()
	w.secretname = secretname
	w.versionstage = versionstage
	w.dlTicker.Reset(frequency)
	w.client = client
}

func (w *watcher) run(ctx context.Context) {
	w.getsecret(ctx)
	defer w.dlTicker.Stop()
	for {
		select {
		case <-w.dlTicker.C:
			w.getsecret(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (w *watcher) getsecret(ctx context.Context) {
	w.mut.Lock()
	defer w.mut.Unlock()
	secret, err := w.getSecretValue(context.Background())
	r := result{
		result: secret,
		err:    err,
	}
	select {
	case <-ctx.Done():
		return
	case w.output <- r:
	}
}

func (w *watcher) updateSecret() (map[string]interface{}, error) {
	w.mut.Lock()
	defer w.mut.Unlock()
	buf, err := w.getSecretValue(context.Background())
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (w *watcher) getSecretValue(ctx context.Context) (map[string]interface{}, error) {
	result, err := w.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(w.secretname),
		VersionStage: aws.String(w.versionstage),
	})
	if err != nil {
		return nil, err
	}

	if result.SecretBinary != nil {
		err := errors.New("SecretBinary is not supported")
		return nil, err
	}

	secretString := aws.ToString(result.SecretString)
	res := make(map[string]interface{})
	if err := json.Unmarshal([]byte(secretString), &res); err != nil {
		return nil, err
	}
	return res, nil
}
