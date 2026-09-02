// Package jobscheduler provides the durable scheduler core for explicitly
// submitted jobs. It owns only in-memory admission/execution coordination;
// the jobrecord repository remains the source of truth for lifecycle state.
package jobscheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

var (
	// These admission errors are part of the scheduler contract.
	ErrQueueFull   = jobs.ErrQueueFull
	ErrQueueClosed = jobs.ErrQueueClosed

	// ErrInvalidOptions is returned only for constructor configuration errors.
	ErrInvalidOptions = errors.New("invalid job scheduler options")
	// ErrInvalidSubmission means the caller did not provide a fully valid
	// queued state.Job and executor. No durable write is attempted.
	ErrInvalidSubmission = errors.New("invalid job scheduler submission")
	// ErrPersistenceFailure is the only scheduler error exposed for an
	// unexpected repository failure. It never wraps the repository error.
	ErrPersistenceFailure = errors.New("job scheduler persistence failed")
	// ErrUnhealthy identifies a scheduler closed because durable state could no
	// longer be trusted. It is intentionally free of storage diagnostics.
	ErrUnhealthy = errors.New("job scheduler is unhealthy")
	// ErrInvalidCancellationRequest identifies malformed actor/request metadata.
	// The job ID is deliberately validated by the durable repository so invalid
	// and missing IDs retain the repository's existing jobs.ErrNotFound mapping.
	ErrInvalidCancellationRequest = errors.New("invalid job cancellation request")

	failureCodePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	identifierPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	requestIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	etagPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	maxCancellationActor = 256
)

const (
	FailureCodeExecutorResultInvalid = "executor_result_invalid"
	FailureCodeExecutorPanic         = "executor_panic"

	defaultPersistenceTimeout = 10 * time.Second
	minPersistenceTimeout     = time.Millisecond
	maxPersistenceTimeout     = time.Minute
)

// Executor is deliberately result-only: an executor cannot return an
// arbitrary error or message for persistence. Executors must cooperate with
// ctx; a non-cooperative executor can make Shutdown wait until its caller's
// deadline, while a later Shutdown may retry after the executor returns. The
// scheduler supplies a child context rooted at its lifetime context and a
// defensive running-job copy.
type Executor func(context.Context, state.Job) ExecutionResult

// ExecutionOutcome is an alias of the durable status type. Only succeeded and
// failed are accepted from an executor. Canceled is selected by scheduler
// cancellation only.
type ExecutionOutcome = jobs.Status

const (
	ExecutionSucceeded ExecutionOutcome = jobs.StatusSucceeded
	ExecutionFailed    ExecutionOutcome = jobs.StatusFailed
)

// ExecutionResult is the bounded typed output of an Executor. PlanID and
// ReportID are the only result links representable by state.Job; the
// scheduler applies the existing per-job-type jobrecord rules before writing.
type ExecutionResult struct {
	Outcome     ExecutionOutcome
	PlanID      string
	ReportID    string
	FailureCode string
}

// Submission is one complete durable admission attempt. Job must already be a
// valid queued state.Job and Executor must be non-nil.
type Submission struct {
	Job      state.Job
	Executor Executor
}

// Options configures one scheduler. QueueCapacity is the waiting portion of
// the bounded admission budget; the total slot budget is QueueCapacity plus
// Workers. Now is normalized to UTC at each observation.
type Options struct {
	Repository    Repository
	Workers       int
	QueueCapacity int
	Now           func() time.Time

	// PersistenceTimeout bounds each scheduler-owned repository operation. A
	// zero value uses the safe ten-second default; non-zero values must be
	// between one millisecond and one minute, inclusive.
	PersistenceTimeout time.Duration
}

// Repository is the minimal durable transition surface needed by this core.
// It intentionally excludes recovery, interruption, and unrelated read/write
// operations from the scheduler dependency.
type Repository interface {
	Create(context.Context, state.Job) (jobrecord.Record, error)
	Get(context.Context, string) (jobrecord.Record, error)
	Put(context.Context, string, state.Job, string) (jobrecord.Record, error)
}

// CancellationRepository is the optional narrow durable cancellation surface.
// Keeping it separate lets existing scheduler repositories and test fakes
// remain valid until they intentionally support durable cancellation.
type CancellationRepository interface {
	RequestCancellation(context.Context, string, string) (jobrecord.Record, error)
}

var _ Repository = (*jobrecord.FileRepository)(nil)
var _ CancellationRepository = (*jobrecord.FileRepository)(nil)

// Scheduler owns workers and a root context independent of Submit callers.
type Scheduler struct {
	repository         Repository
	now                func() time.Time
	persistenceTimeout time.Duration
	root               context.Context
	cancel             context.CancelFunc

	// admission serializes the durable-create/enqueue boundary, lifecycle
	// CASes, and the shutdown lifecycle barrier.
	admission chan struct{}
	closed    atomic.Bool // immediate admission closure; not lifecycle stop
	stopping  atomic.Bool // set only by the shutdown coordinator or fatal path
	fatal     atomic.Bool

	slots chan struct{}

	queueMu sync.Mutex
	pending []workItem
	notify  chan struct{}

	workers      sync.WaitGroup
	done         chan struct{}
	shutdownOnce sync.Once

	// active, claimed, and dequeued are admission-guarded ownership markers.
	// claimed/dequeued distinguish the short claim-to-registration and
	// dequeue-to-claim windows from an unrelated durable owner.
	active   map[string]context.CancelFunc
	claimed  map[string]struct{}
	dequeued map[string]struct{}
	owned    map[string]state.Job
}

type workItem struct {
	job      state.Job
	executor Executor
}

// New validates options, creates the scheduler-owned root context, and starts
// exactly Workers worker goroutines. It does not enumerate or resume durable
// records; startup recovery remains the caller/runtime's responsibility.
func New(options Options) (*Scheduler, error) {
	if options.Repository == nil || options.Workers < 1 || options.Workers > 32 || options.QueueCapacity < 1 || options.QueueCapacity > 10000 {
		return nil, ErrInvalidOptions
	}
	persistenceTimeout := options.PersistenceTimeout
	if persistenceTimeout == 0 {
		persistenceTimeout = defaultPersistenceTimeout
	}
	if persistenceTimeout < minPersistenceTimeout || persistenceTimeout > maxPersistenceTimeout {
		return nil, ErrInvalidOptions
	}
	clock := options.Now
	if clock == nil {
		clock = time.Now
	}
	root, cancel := context.WithCancel(context.Background())
	scheduler := &Scheduler{
		repository:         options.Repository,
		now:                clock,
		persistenceTimeout: persistenceTimeout,
		root:               root,
		cancel:             cancel,
		slots:              make(chan struct{}, options.QueueCapacity+options.Workers),
		notify:             make(chan struct{}),
		done:               make(chan struct{}),
		admission:          make(chan struct{}, 1),
		active:             make(map[string]context.CancelFunc),
		claimed:            make(map[string]struct{}),
		dequeued:           make(map[string]struct{}),
		owned:              make(map[string]state.Job),
	}
	scheduler.admission <- struct{}{}
	for index := 0; index < options.Workers; index++ {
		scheduler.workers.Add(1)
		go scheduler.worker()
	}
	go func() {
		scheduler.workers.Wait()
		close(scheduler.done)
	}()
	return scheduler, nil
}

// Submit durably creates and enqueues one job. The submitting context gates
// only admission through Create. Once Create succeeds, the accepted item is
// enqueued under the same admission lock; a later cancellation request may
// affect it only through the scheduler's durable cancellation path.
func (scheduler *Scheduler) Submit(ctx context.Context, submission Submission) (state.Job, error) {
	record, err := scheduler.submitRecord(ctx, submission)
	if err != nil {
		return state.Job{}, err
	}
	return cloneJob(record.Job), nil
}

// RequestCancellation durably requests cooperative cancellation. The caller's
// context gates admission and every operation until its descriptor-relative
// CAS write begins. Once that write begins, its outcome is authoritative even
// if the caller context is canceled: statefs writes are not cancellable.
func (scheduler *Scheduler) RequestCancellation(ctx context.Context, request jobs.CancellationRequest) (jobs.Job, error) {
	ctx = nonNilContext(ctx)
	if err := contextErr(ctx); err != nil {
		return jobs.Job{}, err
	}
	if scheduler.fatal.Load() {
		return jobs.Job{}, ErrUnhealthy
	}
	if scheduler.closed.Load() || scheduler.stopping.Load() || scheduler.root.Err() != nil {
		return jobs.Job{}, ErrQueueClosed
	}
	if err := validateCancellationRequest(request); err != nil {
		return jobs.Job{}, err
	}
	repository, supported := scheduler.repository.(CancellationRepository)
	if !supported || repository == nil {
		return jobs.Job{}, jobs.ErrCancellationUnsupported
	}
	if err := scheduler.acquireAdmission(ctx); err != nil {
		return jobs.Job{}, err
	}
	defer scheduler.releaseAdmission()

	if scheduler.fatal.Load() {
		return jobs.Job{}, ErrUnhealthy
	}
	if scheduler.closed.Load() || scheduler.stopping.Load() || scheduler.root.Err() != nil {
		return jobs.Job{}, ErrQueueClosed
	}

	for attempts := 0; attempts < 8; attempts++ {
		if err := contextErr(ctx); err != nil {
			return jobs.Job{}, err
		}
		current, err := scheduler.repositoryGetForRequest(ctx, request.JobID)
		if err != nil {
			return jobs.Job{}, err
		}
		// A cancellation observed after the read but before the mutation still
		// gates the mutation. The check is deliberately before any CAS begins.
		if err := contextErr(ctx); err != nil {
			return jobs.Job{}, err
		}
		if !validRecord(current, request.JobID) {
			scheduler.failLocked()
			return jobs.Job{}, ErrPersistenceFailure
		}
		if terminalStatus(current.Job.Status) {
			if current.Job.Status != jobs.StatusCanceled || !current.Job.CancellationRequested {
				return jobs.Job{}, jobs.ErrCancellationUnsupported
			}
			if !scheduler.validOwnedTerminalCancellationLocked(request.JobID, current.Job) {
				scheduler.failLocked()
				return jobs.Job{}, ErrPersistenceFailure
			}
			// A validated terminal cancellation is consumed exactly once. A
			// pending item releases its slot here; a dequeued/active worker owns
			// its slot and will release it in its normal worker path.
			scheduler.cleanupTerminalCancellationLocked(request.JobID)
			return projectJob(current.Job), nil
		}

		pending := current.Job.Status == jobs.StatusQueued && scheduler.pendingContains(request.JobID)
		owned, isOwned := scheduler.owned[request.JobID]
		if !isOwned || (!sameJob(current.Job, owned) && !cancellationOnlyJob(owned, current.Job)) {
			scheduler.failLocked()
			return jobs.Job{}, ErrPersistenceFailure
		}
		if current.Job.Status == jobs.StatusQueued {
			if !pending {
				if _, dequeued := scheduler.dequeued[request.JobID]; !dequeued {
					scheduler.failLocked()
					return jobs.Job{}, ErrPersistenceFailure
				}
			}

			// Queued cancellation is one durable mutation. In particular, never
			// publish queued+cancellationRequested and then terminalize it: that
			// two-write window could strand a record for recovery.
			terminal, putErr := scheduler.cancelQueuedLocked(ctx, current)
			if putErr != nil {
				if errors.Is(putErr, jobs.ErrConflict) {
					continue
				}
				if ctx.Err() != nil && (errors.Is(putErr, context.Canceled) || errors.Is(putErr, context.DeadlineExceeded)) {
					return jobs.Job{}, ctx.Err()
				}
				scheduler.failLocked()
				return jobs.Job{}, ErrPersistenceFailure
			}
			if !scheduler.validOwnedTerminalCancellationLocked(request.JobID, terminal.Job) {
				scheduler.failLocked()
				return jobs.Job{}, ErrPersistenceFailure
			}
			scheduler.cleanupTerminalCancellationLocked(request.JobID)
			return projectJob(terminal.Job), nil
		}
		if current.Job.Status != jobs.StatusRunning {
			scheduler.failLocked()
			return jobs.Job{}, ErrPersistenceFailure
		}
		if _, active := scheduler.active[request.JobID]; !active {
			if _, claiming := scheduler.claimed[request.JobID]; !claiming {
				scheduler.failLocked()
				return jobs.Job{}, ErrPersistenceFailure
			}
		}
		// Do not start the durable flag CAS after caller cancellation. The
		// repository repeats this gate immediately before its non-cancellable
		// descriptor-relative write.
		if err := contextErr(ctx); err != nil {
			return jobs.Job{}, err
		}

		updated, err := scheduler.repositoryRequestCancellation(ctx, repository, request.JobID, current.ETag)
		if err != nil {
			if errors.Is(err, jobs.ErrConflict) {
				continue
			}
			// The record was nonterminal at the serialized read above. A
			// subsequent not-found/unsupported result therefore indicates an
			// external owner or an inconsistent repository, not a safe user
			// outcome.
			if errors.Is(err, jobs.ErrNotFound) || errors.Is(err, jobs.ErrCancellationUnsupported) {
				scheduler.failLocked()
				return jobs.Job{}, ErrPersistenceFailure
			}
			return jobs.Job{}, scheduler.mapCancellationRepositoryError(ctx, err)
		}
		if !validRecord(updated, request.JobID) || !validCancellationResult(current, updated, owned) {
			scheduler.failLocked()
			return jobs.Job{}, ErrPersistenceFailure
		}

		switch updated.Job.Status {
		case jobs.StatusRunning:
			if cancel := scheduler.active[request.JobID]; cancel != nil {
				cancel()
			}
			return projectJob(updated.Job), nil
		case jobs.StatusCanceled:
			// An external owner may complete cancellation between our Get and
			// RequestCancellation. It is safe only after exact derivation and
			// terminal validation above.
			scheduler.cleanupTerminalCancellationLocked(request.JobID)
			return projectJob(updated.Job), nil
		default:
			scheduler.failLocked()
			return jobs.Job{}, ErrPersistenceFailure
		}
	}

	// Repeated conflicts mean this scheduler cannot establish ownership of the
	// durable record. Never report a cancellation success in that state.
	scheduler.failLocked()
	return jobs.Job{}, ErrPersistenceFailure
}

func validateCancellationRequest(request jobs.CancellationRequest) error {
	if request.ActorSubject == "" || request.ActorSubject != strings.TrimSpace(request.ActorSubject) || len(request.ActorSubject) > maxCancellationActor || !utf8.ValidString(request.ActorSubject) {
		return ErrInvalidCancellationRequest
	}
	for _, character := range request.ActorSubject {
		if unicode.IsControl(character) {
			return ErrInvalidCancellationRequest
		}
	}
	if !requestIDPattern.MatchString(request.RequestID) {
		return ErrInvalidCancellationRequest
	}
	return nil
}

func projectJob(value state.Job) jobs.Job {
	return jobs.Job{
		ID: value.ID, Type: value.Type, Status: value.Status,
		CreatedAt: value.CreatedAt, StartedAt: cloneTime(value.StartedAt), FinishedAt: cloneTime(value.FinishedAt),
		ActorSubject: value.Actor.Subject, RequestID: value.RequestID,
		FailureCode: value.FailureCode,
	}
}

func validCancellationResult(before, after jobrecord.Record, owned state.Job) bool {
	if after.Job.Status == jobs.StatusCanceled {
		return validTerminalCancellation(owned, after.Job)
	}
	if before.Job.Status != after.Job.Status || !sameJobWithoutCancellation(before.Job, after.Job) || !after.Job.CancellationRequested {
		return false
	}
	if before.Job.CancellationRequested {
		return before.ETag == after.ETag
	}
	return before.ETag != after.ETag
}

// validTerminalCancellation accepts only the scheduler's canonical terminal
// derivation. The finish time is the one lifecycle field introduced by this
// transition; every identity, link, actor, request, creation, and start field
// must remain byte-for-byte equivalent as a decoded job. validRecord has
// already required a canonical document and a valid UTC finish time.
func validTerminalCancellation(owned, terminal state.Job) bool {
	if (owned.Status != jobs.StatusQueued && owned.Status != jobs.StatusRunning) || owned.CancellationRequested || owned.FinishedAt != nil || owned.FailureCode != "" {
		return false
	}
	if terminal.Status != jobs.StatusCanceled || !terminal.CancellationRequested || terminal.FinishedAt == nil || terminal.FailureCode != "" {
		return false
	}
	expected := cloneJob(owned)
	expected.Status = jobs.StatusCanceled
	expected.FinishedAt = cloneTime(terminal.FinishedAt)
	expected.CancellationRequested = true
	return sameJob(expected, terminal)
}

func (scheduler *Scheduler) repositoryGetForRequest(ctx context.Context, id string) (jobrecord.Record, error) {
	persistenceCtx, cancel := context.WithTimeout(ctx, scheduler.persistenceTimeout)
	record, err := scheduler.repository.Get(persistenceCtx, id)
	timedOut := persistenceCtx.Err() != nil
	callerErr := ctx.Err()
	cancel()
	if err != nil {
		if callerErr != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return jobrecord.Record{}, callerErr
		}
		if (timedOut && callerErr == nil) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			scheduler.failLocked()
			return jobrecord.Record{}, ErrPersistenceFailure
		}
		if errors.Is(err, jobs.ErrNotFound) {
			if scheduler.trackedLocked(id) {
				// A durable record disappearing while this scheduler owns any
				// admission marker is an ambiguous persistence failure. Only an
				// unowned unknown ID retains the public not-found result.
				scheduler.failLocked()
				return jobrecord.Record{}, ErrPersistenceFailure
			}
			return jobrecord.Record{}, jobs.ErrNotFound
		}
		scheduler.failLocked()
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	if timedOut && callerErr == nil {
		scheduler.failLocked()
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	if callerErr != nil {
		return jobrecord.Record{}, callerErr
	}
	return record, nil
}

func (scheduler *Scheduler) repositoryRequestCancellation(ctx context.Context, repository CancellationRepository, id, expectedETag string) (jobrecord.Record, error) {
	persistenceCtx, cancel := context.WithTimeout(ctx, scheduler.persistenceTimeout)
	record, err := repository.RequestCancellation(persistenceCtx, id, expectedETag)
	timedOut := persistenceCtx.Err() != nil
	callerErr := ctx.Err()
	cancel()
	if err != nil {
		if callerErr != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return jobrecord.Record{}, callerErr
		}
		if (timedOut && callerErr == nil) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			scheduler.failLocked()
			return jobrecord.Record{}, ErrPersistenceFailure
		}
		return jobrecord.Record{}, err
	}
	// A nil error is authoritative: RequestCancellation returns only after
	// its descriptor-relative CAS has completed (or an idempotent durable
	// replay was read). Do not turn a concurrent caller/persistence-context
	// cancellation into a failure after that point.
	return record, nil
}

func (scheduler *Scheduler) mapCancellationRepositoryError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, jobs.ErrCancellationUnsupported):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fallthrough
	default:
		scheduler.failLocked()
		return ErrPersistenceFailure
	}
}

func (scheduler *Scheduler) submitRecord(ctx context.Context, submission Submission) (jobrecord.Record, error) {
	ctx = nonNilContext(ctx)
	if err := contextErr(ctx); err != nil {
		return jobrecord.Record{}, err
	}
	if submission.Executor == nil || submission.Job.Status != jobs.StatusQueued || submission.Job.Validate() != nil || submission.Job.CancellationRequested || !validPersistedLinks(submission.Job) {
		return jobrecord.Record{}, ErrInvalidSubmission
	}
	job := cloneJob(submission.Job)
	if err := scheduler.acquireAdmission(ctx); err != nil {
		return jobrecord.Record{}, err
	}
	defer scheduler.releaseAdmission()
	if err := contextErr(ctx); err != nil {
		return jobrecord.Record{}, err
	}
	if scheduler.closed.Load() || scheduler.fatal.Load() {
		return jobrecord.Record{}, ErrQueueClosed
	}

	select {
	case scheduler.slots <- struct{}{}:
	default:
		return jobrecord.Record{}, ErrQueueFull
	}
	reserved := true
	defer func() {
		if reserved {
			scheduler.releaseSlot()
		}
	}()

	persistenceCtx, cancel := context.WithTimeout(ctx, scheduler.persistenceTimeout)
	record, err := scheduler.repository.Create(persistenceCtx, job)
	persistenceErr := persistenceCtx.Err()
	callerErr := ctx.Err()
	cancel()
	if err != nil {
		return jobrecord.Record{}, scheduler.mapCreateError(callerErr, persistenceErr, err)
	}
	if persistenceErr != nil && callerErr == nil {
		// A repository that reports success after the scheduler-owned deadline
		// has an unknown durability boundary. Leave any durable record for
		// startup recovery rather than publishing an unbounded admission.
		scheduler.failLocked()
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	// A successful Create is durable. Validate both the returned ownership and
	// the exact accepted job before publishing it to the in-memory queue.
	if !validRecord(record, job.ID) || !sameJob(record.Job, job) {
		scheduler.failLocked()
		return jobrecord.Record{}, ErrPersistenceFailure
	}

	// Never select on ctx or root after a successful Create: accepted work must
	// be represented in memory exactly once.
	scheduler.owned[job.ID] = cloneJob(record.Job)
	scheduler.enqueue(workItem{job: cloneJob(record.Job), executor: submission.Executor})
	reserved = false
	return record, nil
}

// Health reports nil while admission is open and durable persistence is
// trusted. Normal shutdown reports ErrQueueClosed; a fatal persistence event
// reports ErrUnhealthy and never the underlying storage error.
func (scheduler *Scheduler) Health() error {
	if scheduler.fatal.Load() {
		return ErrUnhealthy
	}
	if scheduler.closed.Load() {
		return ErrQueueClosed
	}
	return nil
}

// Shutdown immediately closes admission, then starts one asynchronous
// lifecycle coordinator. The coordinator waits for the admission token before
// setting stopping and canceling the root, so a lifecycle operation already
// under admission may linearize before shutdown. Every caller waits on the
// same worker lifecycle and may supply an independent deadline.
func (scheduler *Scheduler) Shutdown(ctx context.Context) error {
	ctx = nonNilContext(ctx)
	scheduler.closed.Store(true)
	scheduler.signal()
	scheduler.shutdownOnce.Do(func() { go scheduler.coordinateShutdown() })

	select {
	case <-scheduler.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (scheduler *Scheduler) coordinateShutdown() {
	// Admission operations use scheduler-owned persistence deadlines. The
	// coordinator itself deliberately has no caller deadline: a timed-out
	// Shutdown caller must not prevent eventual lifecycle linearization.
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		return
	}
	scheduler.stopping.Store(true)
	scheduler.cancel()
	scheduler.signal()
	scheduler.releaseAdmission()
}

func (scheduler *Scheduler) worker() {
	defer scheduler.workers.Done()
	for {
		item, ok := scheduler.next()
		if !ok {
			return
		}
		scheduler.run(item)
		scheduler.releaseSlot()
	}
}

func (scheduler *Scheduler) next() (workItem, bool) {
	for {
		if err := scheduler.acquireAdmission(context.Background()); err != nil {
			return workItem{}, false
		}
		scheduler.queueMu.Lock()
		if len(scheduler.pending) > 0 {
			item := scheduler.pending[0]
			scheduler.pending[0] = workItem{}
			scheduler.pending = scheduler.pending[1:]
			scheduler.dequeued[item.job.ID] = struct{}{}
			scheduler.queueMu.Unlock()
			scheduler.releaseAdmission()
			return item, true
		}
		wait := scheduler.notify
		stopped := scheduler.stopped()
		scheduler.queueMu.Unlock()
		scheduler.releaseAdmission()

		if stopped {
			return workItem{}, false
		}
		<-wait
	}
}

func (scheduler *Scheduler) run(item workItem) {
	record, claimed := scheduler.claim(item.job)
	if !claimed {
		return
	}

	jobContext, cancel := context.WithCancel(scheduler.root)
	if !scheduler.registerActive(record.Job, record.ETag, cancel) {
		cancel()
		return
	}
	defer func() {
		cancel()
		scheduler.unregisterActive(record.Job.ID)
	}()
	result, panicked := invoke(item.executor, jobContext, cloneJob(record.Job))
	scheduler.finish(record.Job.ID, record.ETag, record.Job, result, panicked)
}

func (scheduler *Scheduler) registerActive(claimed state.Job, claimedETag string, cancel context.CancelFunc) bool {
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		return false
	}
	defer scheduler.releaseAdmission()
	if _, claimedMarker := scheduler.claimed[claimed.ID]; !claimedMarker {
		// Request cancellation retains the claim marker until this worker has
		// observed and validated the durable terminal record. Its absence is
		// therefore an internal ownership failure, never a harmless replay.
		scheduler.failLocked()
		return false
	}
	if _, owned := scheduler.owned[claimed.ID]; !owned {
		scheduler.failLocked()
		return false
	}
	scheduler.active[claimed.ID] = cancel
	current, err := scheduler.repositoryGet(claimed.ID)
	if err != nil || !validRecord(current, claimed.ID) {
		scheduler.clearOwnershipMarkersLocked(claimed.ID)
		scheduler.failLocked()
		return false
	}
	if current.Job.Status == jobs.StatusCanceled && current.Job.CancellationRequested {
		// A terminal cancellation can win in the claim-to-registration gap.
		// It is safe only when exactly derived from the retained worker claim.
		if !scheduler.consumeOwnedTerminalCancellationLocked(claimed.ID, current.Job) {
			scheduler.failLocked()
			return false
		}
		return false
	}
	if current.Job.Status != jobs.StatusRunning || !sameJobWithoutCancellation(current.Job, claimed) || (current.Job.CancellationRequested && current.ETag == claimedETag) || (!current.Job.CancellationRequested && current.ETag != claimedETag) {
		scheduler.clearOwnershipMarkersLocked(claimed.ID)
		scheduler.failLocked()
		return false
	}
	if current.Job.CancellationRequested {
		// The durable request may have won in the claim-to-registration gap.
		// Registration precedes this cancel, so a racing request cannot miss it.
		cancel()
	}
	delete(scheduler.claimed, claimed.ID)
	return true
}

func (scheduler *Scheduler) unregisterActive(id string) {
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		return
	}
	scheduler.clearOwnershipMarkersLocked(id)
	scheduler.releaseAdmission()
}

func (scheduler *Scheduler) claim(expected state.Job) (jobrecord.Record, bool) {
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		return jobrecord.Record{}, false
	}
	admissionHeld := true
	defer func() {
		if admissionHeld {
			scheduler.releaseAdmission()
		}
	}()

	for attempts := 0; attempts < 8; attempts++ {
		// This check is meaningful only while holding admission. Closed alone is
		// intentionally excluded: shutdown has not yet linearized stopping.
		if scheduler.cancellationLocked() {
			scheduler.releaseAdmission()
			admissionHeld = false
			scheduler.cancelQueued(expected)
			return jobrecord.Record{}, false
		}

		record, err := scheduler.repositoryGet(expected.ID)
		if err != nil {
			scheduler.failLocked()
			return jobrecord.Record{}, false
		}
		if !validRecord(record, expected.ID) {
			scheduler.failLocked()
			return jobrecord.Record{}, false
		}
		if record.Job.Status == jobs.StatusQueued && cancellationOnlyJob(expected, record.Job) {
			terminal, putErr := scheduler.cancelQueuedLocked(context.Background(), record)
			if putErr != nil {
				if errors.Is(putErr, jobs.ErrConflict) {
					continue
				}
				scheduler.failLocked()
				return jobrecord.Record{}, false
			}
			if !scheduler.consumeOwnedTerminalCancellationLocked(expected.ID, terminal.Job) {
				scheduler.failLocked()
				return jobrecord.Record{}, false
			}
			return jobrecord.Record{}, false
		}
		if record.Job.Status == jobs.StatusCanceled && record.Job.CancellationRequested {
			// A terminal cancellation may have won after dequeue but before this
			// claim. The dequeued worker retains its durable baseline until this
			// exact validation and marker consumption.
			if !scheduler.consumeOwnedTerminalCancellationLocked(expected.ID, record.Job) {
				scheduler.failLocked()
				return jobrecord.Record{}, false
			}
			return jobrecord.Record{}, false
		}
		if !sameJob(record.Job, expected) || record.Job.Status != jobs.StatusQueued {
			// An accepted queued job that is already running or terminal has an
			// ambiguous external owner. Leave it for startup recovery.
			scheduler.failLocked()
			return jobrecord.Record{}, false
		}
		started, ok := scheduler.timestampAtLeast(record.Job.CreatedAt)
		if !ok {
			scheduler.failLocked()
			return jobrecord.Record{}, false
		}
		running := cloneJob(record.Job)
		running.Status = jobs.StatusRunning
		running.StartedAt = &started
		updated, putErr := scheduler.repositoryPut(expected.ID, running, record.ETag)
		if putErr == nil {
			if !validRecord(updated, expected.ID) || !sameJob(updated.Job, running) {
				scheduler.failLocked()
				return jobrecord.Record{}, false
			}
			delete(scheduler.dequeued, expected.ID)
			scheduler.owned[expected.ID] = cloneJob(updated.Job)
			scheduler.claimed[expected.ID] = struct{}{}
			return updated, true
		}
		if errors.Is(putErr, jobs.ErrConflict) {
			continue
		}
		scheduler.failLocked()
		return jobrecord.Record{}, false
	}
	// Repeated stale conflicts leave ownership unknowable. Close admission and
	// leave the durable queued record for startup recovery.
	scheduler.failLocked()
	return jobrecord.Record{}, false
}

func (scheduler *Scheduler) finish(id, claimedETag string, claimed state.Job, result ExecutionResult, panicked bool) {
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		return
	}
	defer scheduler.releaseAdmission()

	for attempts := 0; attempts < 8; attempts++ {
		current, err := scheduler.repositoryGet(id)
		if err != nil {
			scheduler.failLocked()
			return
		}
		if !validRecord(current, id) {
			scheduler.failLocked()
			return
		}
		if current.Job.Status == jobs.StatusCanceled && current.Job.CancellationRequested {
			// This worker retains the scheduler-owned baseline until it observes
			// the terminal record. Never accept a terminal replay without it.
			if !scheduler.consumeOwnedTerminalCancellationLocked(id, current.Job) {
				scheduler.failLocked()
				return
			}
			return
		}
		cancellationOnly := current.Job.Status == jobs.StatusRunning && current.ETag != claimedETag && cancellationOnlyJob(claimed, current.Job)
		if (!cancellationOnly && (current.ETag != claimedETag || !sameJob(current.Job, claimed))) || current.Job.Status != jobs.StatusRunning {
			// The claim is no longer provably ours, except for the one authorized
			// durable cancellation-only mutation. Do not overwrite ambiguity.
			scheduler.failLocked()
			return
		}

		status, failureCode, planID, reportID := scheduler.normalizedResult(current.Job, result, panicked)
		// Durable cancellation and scheduler shutdown/fatal cancellation both
		// take precedence over the executor result. The former is not fatal.
		if cancellationOnly || current.Job.CancellationRequested || scheduler.cancellationLocked() {
			status, failureCode = jobs.StatusCanceled, ""
			planID, reportID = current.Job.PlanID, current.Job.ReportID
		}
		finished, ok := scheduler.timestampAtLeast(finishFloor(current.Job, claimed))
		if !ok {
			scheduler.failLocked()
			return
		}
		replacement := cloneJob(current.Job)
		replacement.Status = status
		replacement.FinishedAt = &finished
		replacement.FailureCode = failureCode
		replacement.PlanID = planID
		replacement.ReportID = reportID
		updated, putErr := scheduler.repositoryPut(id, replacement, current.ETag)
		if putErr == nil {
			if !validRecord(updated, id) || !sameJob(updated.Job, replacement) {
				scheduler.failLocked()
				return
			}
			scheduler.clearOwnershipMarkersLocked(id)
			return
		}
		if errors.Is(putErr, jobs.ErrConflict) {
			continue
		}
		scheduler.failLocked()
		return
	}
	scheduler.failLocked()
}

func (scheduler *Scheduler) cancelQueued(expected state.Job) {
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		return
	}
	defer scheduler.releaseAdmission()
	for attempts := 0; attempts < 8; attempts++ {
		record, err := scheduler.repositoryGet(expected.ID)
		if err != nil {
			scheduler.failLocked()
			return
		}
		if !validRecord(record, expected.ID) {
			scheduler.failLocked()
			return
		}
		if record.Job.Status == jobs.StatusCanceled && record.Job.CancellationRequested {
			if !scheduler.consumeOwnedTerminalCancellationLocked(expected.ID, record.Job) {
				scheduler.failLocked()
				return
			}
			return
		}
		if record.Job.Status != jobs.StatusQueued || (!sameJob(record.Job, expected) && !cancellationOnlyJob(expected, record.Job)) {
			scheduler.failLocked()
			return
		}
		terminal, putErr := scheduler.cancelQueuedLocked(context.Background(), record)
		if putErr == nil {
			if !scheduler.consumeOwnedTerminalCancellationLocked(expected.ID, terminal.Job) {
				scheduler.failLocked()
				return
			}
			return
		}
		if errors.Is(putErr, jobs.ErrConflict) {
			continue
		}
		scheduler.failLocked()
		return
	}
	scheduler.failLocked()
}

// cancelQueuedLocked terminalizes a queued record while the scheduler owns
// admission. It deliberately performs one CAS write containing both the
// terminal status and cancellationRequested=true; no intermediate queued+
// requested state is published by the scheduler.
func (scheduler *Scheduler) cancelQueuedLocked(ctx context.Context, record jobrecord.Record) (jobrecord.Record, error) {
	if record.Job.Status != jobs.StatusQueued {
		return jobrecord.Record{}, jobs.ErrInvalidTransition
	}
	finished, ok := scheduler.timestampAtLeast(record.Job.CreatedAt)
	if !ok {
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	replacement := cloneJob(record.Job)
	replacement.Status = jobs.StatusCanceled
	replacement.CancellationRequested = true
	replacement.FinishedAt = &finished
	updated, putErr := scheduler.repositoryPutForCancellation(ctx, record.Job.ID, replacement, record.ETag)
	if putErr != nil {
		return jobrecord.Record{}, putErr
	}
	if !validRecord(updated, record.Job.ID) || !sameJob(updated.Job, replacement) {
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	return updated, nil
}

// trackedLocked reports scheduler ownership while admission is held. A
// durable disappearance is fatal for every marker, including the short
// dequeue/claim windows where no executor is active yet.
func (scheduler *Scheduler) trackedLocked(id string) bool {
	if _, tracked := scheduler.owned[id]; tracked {
		return true
	}
	if _, tracked := scheduler.claimed[id]; tracked {
		return true
	}
	if _, tracked := scheduler.dequeued[id]; tracked {
		return true
	}
	if _, tracked := scheduler.active[id]; tracked {
		return true
	}
	return scheduler.pendingContains(id)
}

func (scheduler *Scheduler) validOwnedTerminalCancellationLocked(id string, terminal state.Job) bool {
	if !scheduler.trackedLocked(id) {
		// A valid terminal canceled record with no in-memory marker is a
		// restart/historical replay and has no scheduler baseline to compare.
		return true
	}
	owned, ok := scheduler.owned[id]
	return ok && validTerminalCancellation(owned, terminal)
}

// consumeOwnedTerminalCancellationLocked validates the terminal cancellation
// observed by a scheduler-owned worker against its retained baseline, then
// consumes every ownership marker. The worker loop, not this helper, releases
// the slot reserved by dequeued work.
func (scheduler *Scheduler) consumeOwnedTerminalCancellationLocked(id string, terminal state.Job) bool {
	owned, ok := scheduler.owned[id]
	if !ok || !validTerminalCancellation(owned, terminal) {
		return false
	}
	if cancel := scheduler.active[id]; cancel != nil {
		cancel()
	}
	scheduler.clearOwnershipMarkersLocked(id)
	return true
}

// cleanupTerminalCancellationLocked is the request-side terminal cleanup.
// Pending work is still represented by a queue item, so the request removes
// it and releases its slot. Once a worker has dequeued the item, that worker
// owns the slot and must retain the baseline and markers until it observes the
// exact durable terminal state.
func (scheduler *Scheduler) cleanupTerminalCancellationLocked(id string) {
	if scheduler.removePending(id) {
		if cancel := scheduler.active[id]; cancel != nil {
			cancel()
		}
		scheduler.releaseSlot()
		scheduler.clearOwnershipMarkersLocked(id)
		return
	}
	if cancel := scheduler.active[id]; cancel != nil {
		cancel()
	}
}

func (scheduler *Scheduler) clearOwnershipMarkersLocked(id string) {
	delete(scheduler.active, id)
	delete(scheduler.claimed, id)
	delete(scheduler.dequeued, id)
	delete(scheduler.owned, id)
}

func (scheduler *Scheduler) pendingContains(id string) bool {
	scheduler.queueMu.Lock()
	defer scheduler.queueMu.Unlock()
	for _, item := range scheduler.pending {
		if item.job.ID == id {
			return true
		}
	}
	return false
}

func (scheduler *Scheduler) removePending(id string) bool {
	scheduler.queueMu.Lock()
	defer scheduler.queueMu.Unlock()
	for index, item := range scheduler.pending {
		if item.job.ID != id {
			continue
		}
		copy(scheduler.pending[index:], scheduler.pending[index+1:])
		last := len(scheduler.pending) - 1
		scheduler.pending[last] = workItem{}
		scheduler.pending = scheduler.pending[:last]
		return true
	}
	return false
}

func (scheduler *Scheduler) normalizedResult(job state.Job, result ExecutionResult, panicked bool) (jobs.Status, string, string, string) {
	if panicked {
		return jobs.StatusFailed, FailureCodeExecutorPanic, job.PlanID, job.ReportID
	}
	outcome, valid := resultOutcome(result)
	if !valid {
		return jobs.StatusFailed, FailureCodeExecutorResultInvalid, job.PlanID, job.ReportID
	}
	if outcome == jobs.StatusFailed {
		if !failureCodePattern.MatchString(result.FailureCode) || result.PlanID != "" || result.ReportID != "" {
			return jobs.StatusFailed, FailureCodeExecutorResultInvalid, job.PlanID, job.ReportID
		}
		return jobs.StatusFailed, result.FailureCode, job.PlanID, job.ReportID
	}
	if result.FailureCode != "" || !validResultLinks(job, result.PlanID, result.ReportID) {
		return jobs.StatusFailed, FailureCodeExecutorResultInvalid, job.PlanID, job.ReportID
	}
	planID, reportID := job.PlanID, job.ReportID
	if result.PlanID != "" {
		planID = result.PlanID
	}
	if result.ReportID != "" {
		reportID = result.ReportID
	}
	return jobs.StatusSucceeded, "", planID, reportID
}

func resultOutcome(result ExecutionResult) (jobs.Status, bool) {
	if result.Outcome != jobs.StatusSucceeded && result.Outcome != jobs.StatusFailed {
		return "", false
	}
	return result.Outcome, true
}

func validResultLinks(job state.Job, planID, reportID string) bool {
	if planID != "" && !identifierPattern.MatchString(planID) {
		return false
	}
	if reportID != "" && !identifierPattern.MatchString(reportID) {
		return false
	}
	switch job.Type {
	case jobs.TypeValidation, jobs.TypeTargetInventory:
		return planID == "" && reportID == ""
	case jobs.TypePlan:
		return reportID == "" && job.PlanID == ""
	case jobs.TypeApply:
		if job.PlanID == "" || (planID != "" && planID != job.PlanID) {
			return false
		}
		return true
	default:
		return false
	}
}

func invoke(executor Executor, ctx context.Context, job state.Job) (result ExecutionResult, panicked bool) {
	defer func() {
		if recover() != nil {
			result = ExecutionResult{}
			panicked = true
		}
	}()
	return executor(ctx, cloneJob(job)), false
}

func (scheduler *Scheduler) timestampAtLeast(floor time.Time) (time.Time, bool) {
	value := scheduler.now()
	if value.IsZero() {
		return time.Time{}, false
	}
	value = value.UTC()
	floor = floor.UTC()
	if value.Before(floor) {
		value = floor
	}
	return value, true
}

func finishFloor(current, claimed state.Job) time.Time {
	if current.StartedAt != nil {
		return *current.StartedAt
	}
	if claimed.StartedAt != nil {
		return *claimed.StartedAt
	}
	return current.CreatedAt
}

func (scheduler *Scheduler) enqueue(item workItem) {
	scheduler.queueMu.Lock()
	scheduler.pending = append(scheduler.pending, item)
	scheduler.signalLocked()
	scheduler.queueMu.Unlock()
}

func (scheduler *Scheduler) signal() {
	scheduler.queueMu.Lock()
	scheduler.signalLocked()
	scheduler.queueMu.Unlock()
}

func (scheduler *Scheduler) signalLocked() {
	close(scheduler.notify)
	scheduler.notify = make(chan struct{})
}

func (scheduler *Scheduler) stopped() bool {
	return scheduler.stopping.Load() || scheduler.fatal.Load() || scheduler.root.Err() != nil
}

// cancellationLocked must be called while holding admission. Shutdown and
// fatal transitions are both linearized by this same token.
func (scheduler *Scheduler) cancellationLocked() bool {
	return scheduler.stopping.Load() || scheduler.fatal.Load() || scheduler.root.Err() != nil
}

func (scheduler *Scheduler) releaseSlot() { <-scheduler.slots }

// failLocked is called only by code holding admission. Fatal state closes both
// immediate admission and the lifecycle, and cancels workers without exposing
// repository diagnostics.
func (scheduler *Scheduler) failLocked() {
	scheduler.fatal.Store(true)
	scheduler.closed.Store(true)
	scheduler.stopping.Store(true)
	scheduler.cancel()
	scheduler.signal()
}

func (scheduler *Scheduler) acquireAdmission(ctx context.Context) error {
	select {
	case <-scheduler.admission:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (scheduler *Scheduler) releaseAdmission() { scheduler.admission <- struct{}{} }

func (scheduler *Scheduler) mapCreateError(callerErr, persistenceErr, err error) error {
	// Preserve caller cancellation only when the repository itself reports a
	// context outcome. A simultaneous non-context storage error remains fatal:
	// cancellation must never mask an ambiguous durable write.
	if callerErr != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return callerErr
	}
	if persistenceErr != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		scheduler.failLocked()
		return ErrPersistenceFailure
	}
	switch {
	case errors.Is(err, jobs.ErrConflict), errors.Is(err, statefs.ErrDestinationExists):
		return jobs.ErrConflict
	case errors.Is(err, jobs.ErrInvalidTransition), errors.Is(err, jobrecord.ErrImmutableChange):
		return ErrInvalidSubmission
	case errors.Is(err, state.ErrInvalidDocument), errors.Is(err, state.ErrUnsupportedVersion), errors.Is(err, state.ErrUnsupportedKind):
		return ErrInvalidSubmission
	default:
		scheduler.failLocked()
		return ErrPersistenceFailure
	}
}

func (scheduler *Scheduler) repositoryGet(id string) (jobrecord.Record, error) {
	ctx, cancel := scheduler.persistenceContext()
	record, err := scheduler.repository.Get(ctx, id)
	timedOut := ctx.Err() != nil
	cancel()
	if timedOut {
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	if err != nil {
		return jobrecord.Record{}, err
	}
	return record, nil
}

func (scheduler *Scheduler) repositoryPut(id string, job state.Job, expectedETag string) (jobrecord.Record, error) {
	ctx, cancel := scheduler.persistenceContext()
	record, err := scheduler.repository.Put(ctx, id, job, expectedETag)
	timedOut := ctx.Err() != nil
	cancel()
	if timedOut {
		return jobrecord.Record{}, ErrPersistenceFailure
	}
	if err != nil {
		return jobrecord.Record{}, err
	}
	return record, nil
}

// repositoryPutForCancellation preserves caller cancellation until the
// non-cancellable descriptor-relative Put begins. A successful Put wins even
// when the derived persistence context is canceled concurrently.
func (scheduler *Scheduler) repositoryPutForCancellation(ctx context.Context, id string, job state.Job, expectedETag string) (jobrecord.Record, error) {
	persistenceCtx, cancel := context.WithTimeout(nonNilContext(ctx), scheduler.persistenceTimeout)
	record, err := scheduler.repository.Put(persistenceCtx, id, job, expectedETag)
	timedOut := persistenceCtx.Err() != nil
	callerErr := ctx.Err()
	cancel()
	if err != nil {
		if callerErr != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return jobrecord.Record{}, callerErr
		}
		if timedOut || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return jobrecord.Record{}, ErrPersistenceFailure
		}
		return jobrecord.Record{}, err
	}
	return record, nil
}

func (scheduler *Scheduler) persistenceContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), scheduler.persistenceTimeout)
}

// validRecord is intentionally stricter than the repository decoder: the
// scheduler accepts only canonical bytes for scheduler-owned records. An
// externally noncanonical but decodable document fails closed rather than
// becoming a lifecycle baseline whose bytes the scheduler cannot reproduce.
func validRecord(record jobrecord.Record, expectedID string) bool {
	if record.Job.ID != expectedID || record.Job.Validate() != nil || !validPersistedLinks(record.Job) || !etagPattern.MatchString(record.ETag) {
		return false
	}
	encoded, err := state.EncodeJob(record.Job)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	return record.ETag == hex.EncodeToString(digest[:])
}

func validPersistedLinks(job state.Job) bool {
	switch job.Type {
	case jobs.TypeApply:
		return job.PlanID != "" && (job.ReportID == "" || job.Status == jobs.StatusSucceeded || job.Status == jobs.StatusFailed || job.Status == jobs.StatusCanceled || job.Status == jobs.StatusInterrupted)
	case jobs.TypePlan:
		return (job.PlanID == "" || job.Status == jobs.StatusSucceeded) && job.ReportID == ""
	case jobs.TypeValidation, jobs.TypeTargetInventory:
		return job.PlanID == "" && job.ReportID == ""
	default:
		return false
	}
}

func cancellationOnlyJob(expected, current state.Job) bool {
	return !expected.CancellationRequested && current.CancellationRequested && sameJobWithoutCancellation(expected, current)
}

func sameJobWithoutCancellation(left, right state.Job) bool {
	left.CancellationRequested = false
	right.CancellationRequested = false
	return sameJob(left, right)
}

func sameJob(left, right state.Job) bool {
	return left.APIVersion == right.APIVersion &&
		left.Kind == right.Kind &&
		left.ID == right.ID &&
		left.Type == right.Type &&
		left.Status == right.Status &&
		left.CreatedAt.Equal(right.CreatedAt) &&
		sameTime(left.StartedAt, right.StartedAt) &&
		sameTime(left.FinishedAt, right.FinishedAt) &&
		sameActor(left.Actor, right.Actor) &&
		left.RequestID == right.RequestID &&
		left.IdempotencyKey == right.IdempotencyKey &&
		left.RequestDigest == right.RequestDigest &&
		left.PlanID == right.PlanID &&
		left.ReportID == right.ReportID &&
		left.FailureCode == right.FailureCode &&
		left.CancellationRequested == right.CancellationRequested
}

func sameActor(left, right state.Actor) bool {
	if left.Subject != right.Subject || left.Method != right.Method || len(left.Roles) != len(right.Roles) {
		return false
	}
	for index := range left.Roles {
		if left.Roles[index] != right.Roles[index] {
			return false
		}
	}
	return true
}

func terminalStatus(status jobs.Status) bool {
	return status == jobs.StatusSucceeded || status == jobs.StatusFailed || status == jobs.StatusCanceled || status == jobs.StatusInterrupted
}

func sameTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func cloneJob(value state.Job) state.Job {
	result := value
	result.Actor.Roles = append([]auth.Role(nil), value.Actor.Roles...)
	result.StartedAt = cloneTime(value.StartedAt)
	result.FinishedAt = cloneTime(value.FinishedAt)
	return result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func contextErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
