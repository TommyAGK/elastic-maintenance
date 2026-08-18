package validation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
)

const maxSelectionIDs = 100

type StartRequest struct {
	ActorSubject   string
	RequestID      string
	IdempotencyKey string
	Selection      Selection
}

type Options struct {
	Inputs        InputReader
	Repository    Repository
	Workers       int
	QueueCapacity int
	Clock         jobs.Clock
	IDGenerator   jobs.IDGenerator
}

type Service struct {
	inputs     InputReader
	repository Repository
	clock      jobs.Clock
	generator  jobs.IDGenerator
	queue      chan string
	slots      chan struct{}
	root       context.Context
	stop       context.CancelFunc
	workers    sync.WaitGroup
	mu         sync.Mutex
	closed     bool
	active     map[string]context.CancelFunc
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type randomIDGenerator struct{}

func (randomIDGenerator) NewJobID(jobType jobs.Type) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return string(jobType) + "-" + hex.EncodeToString(value[:]), nil
}

func NewService(options Options) (*Service, error) {
	if options.Inputs == nil {
		return nil, errors.New("validation input reader is required")
	}
	if options.Repository == nil {
		return nil, errors.New("validation repository is required")
	}
	if options.Workers < 1 || options.Workers > 32 {
		return nil, errors.New("validation workers must be between 1 and 32")
	}
	if options.QueueCapacity < 1 || options.QueueCapacity > 10_000 {
		return nil, errors.New("validation queue capacity must be between 1 and 10000")
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	if options.IDGenerator == nil {
		options.IDGenerator = randomIDGenerator{}
	}
	root, stop := context.WithCancel(context.Background())
	service := &Service{
		inputs: options.Inputs, repository: options.Repository, clock: options.Clock, generator: options.IDGenerator,
		queue: make(chan string, options.QueueCapacity), slots: make(chan struct{}, options.QueueCapacity+options.Workers),
		root: root, stop: stop, active: make(map[string]context.CancelFunc),
	}
	for index := 0; index < options.Workers; index++ {
		service.workers.Add(1)
		go service.worker()
	}
	if err := service.recoverRecords(); err != nil {
		stop()
		service.workers.Wait()
		return nil, err
	}
	return service, nil
}

func (service *Service) Start(ctx context.Context, request StartRequest) (jobs.Job, error) {
	selection, err := normalizeSelection(request.Selection)
	if err != nil {
		return jobs.Job{}, err
	}
	digest, err := selectionDigest(selection)
	if err != nil {
		return jobs.Job{}, err
	}
	actor := strings.TrimSpace(request.ActorSubject)
	if existing, findErr := service.repository.FindByIdempotency(ctx, actor, request.IdempotencyKey); findErr == nil {
		if existing.Job.RequestDigest != digest {
			return jobs.Job{}, jobs.ErrConflict
		}
		return existing.Job, nil
	} else if !errors.Is(findErr, jobs.ErrNotFound) {
		return jobs.Job{}, findErr
	}
	queued, err := jobs.NewQueued(jobs.NewJobInput{
		Type: jobs.TypeValidation, ActorSubject: actor, RequestID: request.RequestID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest,
	}, service.clock, service.generator)
	if err != nil {
		return jobs.Job{}, err
	}
	service.mu.Lock()
	closed := service.closed
	service.mu.Unlock()
	if closed {
		return jobs.Job{}, jobs.ErrQueueClosed
	}
	select {
	case service.slots <- struct{}{}:
	default:
		return jobs.Job{}, jobs.ErrQueueFull
	}
	release := true
	defer func() {
		if release {
			<-service.slots
		}
	}()
	record, created, err := service.repository.Create(ctx, Record{Job: queued, Selection: selection})
	if err != nil {
		return jobs.Job{}, err
	}
	if !created {
		return record.Job, nil
	}
	service.mu.Lock()
	closed = service.closed
	service.mu.Unlock()
	if closed {
		service.cancelQueued(context.Background(), record)
		return jobs.Job{}, jobs.ErrQueueClosed
	}
	select {
	case service.queue <- record.Job.ID:
		release = false
		return record.Job, nil
	case <-service.root.Done():
		_, _ = service.cancelQueued(context.Background(), record)
		return jobs.Job{}, jobs.ErrQueueClosed
	case <-ctx.Done():
		_, _ = service.cancelQueued(context.Background(), record)
		return jobs.Job{}, ctx.Err()
	}
}

func (service *Service) Get(ctx context.Context, id string) (Record, error) {
	return service.repository.Get(ctx, id)
}
func (service *Service) List(ctx context.Context, options jobs.ListOptions) (RecordPage, error) {
	return service.repository.List(ctx, options)
}

func (service *Service) Cancel(ctx context.Context, id string) (jobs.Job, error) {
	for attempts := 0; attempts < 8; attempts++ {
		record, err := service.repository.Get(ctx, id)
		if err != nil {
			return jobs.Job{}, err
		}
		if record.Job.Terminal() {
			return record.Job, nil
		}
		if record.Job.Status == jobs.StatusQueued {
			updated, err := service.cancelQueued(ctx, record)
			if errors.Is(err, jobs.ErrConflict) {
				continue
			}
			return updated.Job, err
		}
		record.CancellationRequested = true
		updated, err := service.repository.Put(ctx, record, record.Version)
		if errors.Is(err, jobs.ErrConflict) {
			continue
		}
		if err != nil {
			return jobs.Job{}, err
		}
		service.mu.Lock()
		cancel := service.active[id]
		service.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return updated.Job, nil
	}
	return jobs.Job{}, jobs.ErrConflict
}

func (service *Service) Shutdown(ctx context.Context) error {
	service.mu.Lock()
	alreadyClosed := service.closed
	service.closed = true
	service.mu.Unlock()
	if !alreadyClosed {
		if err := service.persistShutdownCancellation(ctx); err != nil {
			service.stop()
			return err
		}
		service.stop()
	}
	service.mu.Lock()
	for _, cancel := range service.active {
		cancel()
	}
	service.mu.Unlock()
	done := make(chan struct{})
	go func() { service.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (service *Service) worker() {
	defer service.workers.Done()
	for {
		select {
		case <-service.root.Done():
			return
		case id := <-service.queue:
			service.execute(id)
			<-service.slots
		}
	}
}

func (service *Service) execute(id string) {
	record, claimed := service.claim(id)
	if !claimed {
		return
	}
	jobCtx, cancel := context.WithCancel(service.root)
	service.mu.Lock()
	service.active[id] = cancel
	service.mu.Unlock()
	if current, getErr := service.repository.Get(context.Background(), id); getErr == nil && current.CancellationRequested {
		cancel()
	}
	defer func() { cancel(); service.mu.Lock(); delete(service.active, id); service.mu.Unlock() }()

	inputs, readErr := service.inputs.Read(jobCtx)
	var snapshot *manifest.SourceSnapshot
	if readErr == nil {
		snapshot, readErr = manifest.BuildSourceSnapshotContext(jobCtx, inputs.Config, inputs.ResourceSets)
	}
	if jobCtx.Err() != nil {
		service.finish(id, jobs.StatusCanceled, nil, "")
		return
	}
	if readErr != nil {
		service.finish(id, jobs.StatusFailed, failedResult(readErr), "invalid_inputs")
		return
	}
	result, scopeErr := scopeSuccessfulResult(snapshot, record.Selection)
	if scopeErr != nil {
		service.finish(id, jobs.StatusFailed, failedResult(scopeErr), "invalid_selection")
		return
	}
	service.finish(id, jobs.StatusSucceeded, result, "")
}

func (service *Service) claim(id string) (Record, bool) {
	for attempts := 0; attempts < 8; attempts++ {
		record, err := service.repository.Get(context.Background(), id)
		if err != nil {
			service.markWorkerPersistenceFailure(id)
			return Record{}, false
		}
		if record.Job.Terminal() {
			return Record{}, false
		}
		if service.isClosed() || service.root.Err() != nil {
			_, _ = service.cancelQueued(context.Background(), record)
			return Record{}, false
		}
		if record.Job.Status != jobs.StatusQueued {
			return Record{}, false
		}
		now := service.clock.Now().UTC()
		record.Job.Status, record.Job.StartedAt = jobs.StatusRunning, &now
		updated, err := service.repository.Put(context.Background(), record, record.Version)
		if errors.Is(err, jobs.ErrConflict) {
			continue
		}
		if err != nil {
			service.markWorkerPersistenceFailure(id)
			return Record{}, false
		}
		return updated, true
	}
	service.markWorkerPersistenceFailure(id)
	return Record{}, false
}

func (service *Service) isClosed() bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.closed
}

func (service *Service) finish(id string, status jobs.Status, result *Result, failureCode string) {
	for attempts := 0; attempts < 8; attempts++ {
		record, err := service.repository.Get(context.Background(), id)
		if err != nil || record.Job.Terminal() {
			return
		}
		if record.Job.Status != jobs.StatusRunning && !(record.Job.Status == jobs.StatusQueued && status == jobs.StatusCanceled) {
			return
		}
		if record.CancellationRequested || service.root.Err() != nil {
			status, result, failureCode = jobs.StatusCanceled, nil, ""
		}
		now := service.clock.Now().UTC()
		service.mu.Lock()
		if service.closed {
			status, result, failureCode = jobs.StatusCanceled, nil, ""
		}
		record.Job.Status, record.Job.FinishedAt, record.Job.FailureCode, record.Result = status, &now, failureCode, result
		_, err = service.repository.Put(context.Background(), record, record.Version)
		service.mu.Unlock()
		if errors.Is(err, jobs.ErrConflict) {
			continue
		} else if err != nil {
			service.markWorkerPersistenceFailure(id)
			return
		}
		return
	}
	service.markWorkerPersistenceFailure(id)
}

func (service *Service) cancelQueued(ctx context.Context, record Record) (Record, error) {
	now := service.clock.Now().UTC()
	record.Job.Status, record.Job.FinishedAt = jobs.StatusCanceled, &now
	return service.repository.Put(ctx, record, record.Version)
}

func (service *Service) persistShutdownCancellation(ctx context.Context) error {
	records, err := service.outstandingRecords(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Job.Status == jobs.StatusQueued {
			_, err = service.cancelQueued(ctx, record)
		} else {
			record.CancellationRequested = true
			_, err = service.repository.Put(ctx, record, record.Version)
		}
		if err != nil && !errors.Is(err, jobs.ErrConflict) {
			return err
		}
	}
	return nil
}

func (service *Service) recoverRecords() error {
	records, err := service.outstandingRecords(context.Background())
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Job.Status == jobs.StatusRunning {
			now := service.clock.Now().UTC()
			record.Job.Status, record.Job.FinishedAt, record.Job.FailureCode = jobs.StatusInterrupted, &now, "service_restarted"
			if _, err := service.repository.Put(context.Background(), record, record.Version); err != nil {
				return err
			}
			continue
		}
		select {
		case service.slots <- struct{}{}:
			service.queue <- record.Job.ID
		default:
			return errors.New("validation recovery exceeds queue capacity")
		}
	}
	return nil
}

func (service *Service) outstandingRecords(ctx context.Context) ([]Record, error) {
	result := make([]Record, 0)
	pageToken := ""
	for {
		page, err := service.repository.List(ctx, jobs.ListOptions{Types: []jobs.Type{jobs.TypeValidation}, Statuses: []jobs.Status{jobs.StatusQueued, jobs.StatusRunning}, PageSize: 100, PageToken: pageToken})
		if err != nil {
			return nil, err
		}
		result = append(result, page.Records...)
		if page.NextPageToken == "" {
			return result, nil
		}
		pageToken = page.NextPageToken
	}
}

func (service *Service) markWorkerPersistenceFailure(id string) {
	// A repository failure cannot be repaired in memory. Best effort records an
	// interrupted terminal state when the repository becomes available again.
	for attempts := 0; attempts < 2; attempts++ {
		record, err := service.repository.Get(context.Background(), id)
		if err != nil || record.Job.Terminal() {
			return
		}
		now := service.clock.Now().UTC()
		if record.Job.Status == jobs.StatusQueued {
			record.Job.Status, record.Job.FinishedAt, record.Job.FailureCode = jobs.StatusCanceled, &now, ""
		} else if record.Job.Status == jobs.StatusRunning {
			record.Job.Status, record.Job.FinishedAt, record.Job.FailureCode = jobs.StatusInterrupted, &now, "repository_failure"
		} else {
			return
		}
		if _, err = service.repository.Put(context.Background(), record, record.Version); err == nil {
			return
		}
	}
}

func normalizeSelection(selection Selection) (Selection, error) {
	normalize := func(values []string) ([]string, error) {
		if len(values) > maxSelectionIDs {
			return nil, errors.New("validation selection contains too many ids")
		}
		result := append([]string{}, values...)
		sort.Strings(result)
		for index, value := range result {
			if len(value) > 128 || value == "" || strings.ContainsAny(value, " /\\\t\r\n") {
				return nil, errors.New("validation selection contains an invalid id")
			}
			if index != 0 && result[index-1] == value {
				return nil, errors.New("validation selection contains duplicate ids")
			}
		}
		return result, nil
	}
	sets, err := normalize(selection.ResourceSetIDs)
	if err != nil {
		return Selection{}, err
	}
	targets, err := normalize(selection.TargetIDs)
	if err != nil {
		return Selection{}, err
	}
	return Selection{ResourceSetIDs: sets, TargetIDs: targets}, nil
}

func selectionDigest(selection Selection) (string, error) {
	encoded, err := json.Marshal(selection)
	if err != nil {
		return "", fmt.Errorf("marshal validation request: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
