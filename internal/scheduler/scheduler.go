package scheduler

import (
	"context"
	"time"
	_ "time/tzdata" // embed the IANA tz database — the alpine runtime image ships no tzdata

	"github.com/robfig/cron/v3"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// defaultTimezone is used when scheduler.timezone / SCHEDULER_TIMEZONE is unset.
//
// Cron specs here are written as local business hours ("run at 3 AM, off-peak"), but
// robfig/cron defaults to time.Local, and in the container time.Local is UTC — so
// "0 3 * * *" actually fired at 11:00 Taipei time, in the middle of the working day,
// renewing certificates and kicking agents into redeploying. Pinning an explicit
// location keeps the spec meaning what it reads like.
const defaultTimezone = "Asia/Taipei"

// Config holds scheduler configuration.
type Config struct {
	Enabled         bool   `mapstructure:"enabled"`
	RenewalCron     string `mapstructure:"renewal_cron"`
	RenewBeforeDays int    `mapstructure:"renewal_before_days"`
	ExpirySyncCron  string `mapstructure:"expiry_sync_cron"`
	Timezone        string `mapstructure:"timezone"`
}

// Scheduler manages cron jobs with fx lifecycle integration.
type Scheduler struct {
	cron *cron.Cron
	cfg  *Config
	log  *zap.Logger
}

// resolveLocation turns the configured timezone name into a *time.Location.
// A bad name is a config typo, not a reason to take the API down, so it degrades to
// UTC — but loudly, because that silently shifts every cron spec by 8 hours.
func resolveLocation(name string, log *zap.Logger) *time.Location {
	if name == "" {
		name = defaultTimezone
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		log.Error("invalid scheduler timezone, falling back to UTC — cron specs will fire at UTC wall-clock time",
			zap.String("timezone", name), zap.Error(err))
		return time.UTC
	}
	return loc
}

// New creates a new Scheduler.
func New(lc fx.Lifecycle, cfg *Config, log *zap.Logger) *Scheduler {
	loc := resolveLocation(cfg.Timezone, log)
	c := cron.New(
		cron.WithLocation(loc),
		cron.WithLogger(cron.VerbosePrintfLogger(newZapCronLogger(log))),
	)

	s := &Scheduler{
		cron: c,
		cfg:  cfg,
		log:  log,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if !cfg.Enabled {
				log.Info("scheduler disabled")
				return nil
			}
			log.Info("starting scheduler",
				zap.String("renewal_cron", cfg.RenewalCron),
				zap.String("timezone", loc.String()))
			c.Start()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if !cfg.Enabled {
				return nil
			}
			log.Info("stopping scheduler")
			stopCtx := c.Stop()
			<-stopCtx.Done()
			return nil
		},
	})

	return s
}

// AddFunc adds a cron job. Should be called before Start (during fx.Invoke).
func (s *Scheduler) AddFunc(spec string, cmd func()) error {
	_, err := s.cron.AddFunc(spec, cmd)
	return err
}

// zapCronLogger adapts zap.Logger to cron.Logger interface.
type zapCronLogger struct {
	log *zap.SugaredLogger
}

func newZapCronLogger(log *zap.Logger) *zapCronLogger {
	return &zapCronLogger{log: log.Sugar()}
}

func (l *zapCronLogger) Printf(format string, v ...interface{}) {
	l.log.Infof(format, v...)
}
