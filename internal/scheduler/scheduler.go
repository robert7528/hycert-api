package scheduler

import (
	"context"

	"github.com/robfig/cron/v3"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// Config holds scheduler configuration.
type Config struct {
	Enabled          bool   `mapstructure:"enabled"`
	RenewalCron      string `mapstructure:"renewal_cron"`
	RenewBeforeDays  int    `mapstructure:"renewal_before_days"`
	ExpirySyncCron   string `mapstructure:"expiry_sync_cron"`
}

// Scheduler manages cron jobs with fx lifecycle integration.
type Scheduler struct {
	cron *cron.Cron
	cfg  *Config
	log  *zap.Logger
}

// New creates a new Scheduler.
func New(lc fx.Lifecycle, cfg *Config, log *zap.Logger) *Scheduler {
	c := cron.New(cron.WithLogger(cron.VerbosePrintfLogger(newZapCronLogger(log))))

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
			log.Info("starting scheduler", zap.String("renewal_cron", cfg.RenewalCron))
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
