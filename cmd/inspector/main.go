/*
 * Точка входа инспектора действий.
 *
 * Здесь только инициализация и подписка: решения принимают пакеты internal/...,
 * а этот файл собирает их в конвейер и следит, чтобы ответ уходил на каждом
 * пути без исключения.
 *
 * Профили компилируются до подписки: правило с опечаткой обязано обнаруживаться
 * при старте, а не на первом сообщении.
 */

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/audit"
	"github.com/exemt/placitum-action/internal/body"
	"github.com/exemt/placitum-action/internal/config"
	"github.com/exemt/placitum-action/internal/desired"
	"github.com/exemt/placitum-action/internal/livelist"
	"github.com/exemt/placitum-action/internal/policy"
	"github.com/exemt/placitum-action/internal/queue"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-shared/pulse"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	/*
	 * Журнал процесса уезжает в waf.log той же пачкой, что и строки nginx:
	 * контур один, и искать причину отказа по трём десяткам docker-логов
	 * незачем. Приёмник поднимается раньше шины -- строки о том, как читался
	 * конфиг, копятся и уезжают первой же пачкой. Копия, не перенос: stdout
	 * остаётся на месте.
	 */
	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	/*
	 * Порог журнала живой: поколение из KV переставляет его без рестарта
	 * (internal/loglevel). Переменная окружения задаёт стартовое значение.
	 */
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	store, err := policy.NewStore(cfg.ProfilesDir, log)
	if err != nil {
		return err
	}

	snap := store.Current()

	for _, name := range snap.Names() {
		p, _ := snap.Profile(name)
		log.Info("profile loaded", "profile", p.Name, "mode", p.Mode, "rules", len(p.Rules))
	}

	/*
	 * Применённое поколение поднимается до подписки: рестарт до того, как watch
	 * догнал KV, не должен откатывать процесс на файлы из образа.
	 */
	if desired.Bootstrap(store, cfg.DataDir, log) {
		snap = store.Current()
	}

	nc, err := nats.Connect(strings.Join(cfg.Servers, ","),
		nats.Name("waf-inspector-"+cfg.Name),
		// Инспектор переживает перезапуск шины, а не умирает вместе с ней.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("bus reconnected", "server", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	defer nc.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err.Error())
	}

	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	/*
	 * События аудита уезжают пачками, а не по одной на инспекцию: при четырёх
	 * инспекторах в наборе это впятеро больше сообщений, чем запросов, и
	 * партия из одного сообщения кладёт вставку у потребителя.
	 *
	 * Закрывается после пула: в очереди события уже отвеченных запросов.
	 */
	auditSink := audit.NewSink(nc, log)

	/*
	 * Условия профилей: заголовки и строка запроса -- из обменника, наборы --
	 * из зеркала keeper. Наборы заказываются на каждом снимке профилей, чтобы
	 * первый запрос не ждал снапшота; профиль без условий обменник не трогает.
	 */
	loader, closeStore, err := bodyLoader(cfg, log)
	if err != nil {
		return err
	}

	defer closeStore()

	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)

	var sets livelist.Blobs

	if cfg.InternalURL != "" {
		opened, err := livelist.OpenBlobs(cfg.InternalURL)
		if err != nil {
			return err
		}

		defer opened.Close()
		sets = opened
	}

	mirror := livelist.New(nc, sets, log)
	defer mirror.Close()

	store.OnLoad(func(snap *policy.Snapshot) {
		for _, name := range snap.Datasets() {
			mirror.Ensure(name)
		}
	})

	/*
	 * Кодер гео -- для записей в наборы, которые пишут не адрес (net,
	 * net_all, asn). Соединение ленивое: профиль без таких строк кодер не
	 * трогает ни разу. Пусто в окружении -- кодера нет, такие строки отвечают
	 * error.
	 */
	var resolver *netinfo.Resolver

	if cfg.GeoAddr != "" {
		var rerr error

		resolver, rerr = netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
		if rerr != nil {
			return fmt.Errorf("geo resolver: %w", rerr)
		}

		defer resolver.Close()
	}

	h := &handler{cfg: cfg, log: log, nc: nc,
		audit: auditSink, store: store, loader: loader, mirror: mirror,
		lists: dataset.NewBackground(nc, cfg.Name, log), resolver: resolver}

	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS,
		cfg.QueueFull, h.evaluate)
	h.pool = pool

	// Queue group: горизонтальное масштабирование без координации. Ответ уходит
	// в инбокс того воркера nginx, который спрашивал.
	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 8*1024*1024); err != nil {
		return err
	}

	log.Info("connected",
		"server", nc.ConnectedUrl(),
		"subject", cfg.Subject,
		"queue", cfg.Queue,
		"inspector", cfg.Name,
		"profiles", snap.Names(),
		"workers", cfg.Workers,
		"queue_max", cfg.QueueDepth,
		"queue_full", cfg.QueueFull,
		"conf", cfg.ConfPath,
	)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	// Опрос отпечатка каталога: профили правят руками там, где контроллера нет.
	go store.Watch(ctx, cfg.ReloadEvery)

	var applied *desired.Applied

	applied, err = desired.Watch(ctx, nc, store, cfg.DataDir, level, log)
	if err != nil {
		log.Warn("desired watch failed", "error", err.Error())
	} else {
		log.Info("desired watch on",
			"bucket", desired.Bucket,
			"key", desired.Key,
			"data", cfg.DataDir,
		)
	}

	inspectorID := pulse.NewID()
	stopBeat := startHeartbeat(nc, cfg, inspectorID, pool, applied, store, logIO, log)

	defer stopBeat()

	waitForSignal(log)
	stop()

	/*
	 * Дренаж: сначала снимается подписка, потом воркеры дожидаются принятых
	 * сообщений. Без него reload инспектора выглядит на стороне модуля как
	 * всплеск срабатываний политики waf_deadline на его subject.
	 */
	if err := sub.Drain(); err != nil {
		log.Warn("drain failed", "error", err.Error())
	}

	pool.Close()
	auditSink.Close()

	log.Info("drained",
		"accepted", pool.Accepted.Load(),
		"shed", pool.Shed.Load(),
		"expired", pool.Expired.Load(),
	)

	return nil
}

func startHeartbeat(
	nc *nats.Conn,
	cfg *config.Config,
	id string,
	pool *queue.Pool,
	applied *desired.Applied,
	store *policy.Store,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(cfg.Name, id)
	log.Info("heartbeat on", "subject", subject, "id", id, "every", cfg.HeartbeatEvery.String())

	beat := func() {
		work := &pulse.Work{
			Workers:    cfg.Workers,
			QueueDepth: cfg.QueueDepth,
			Queued:     pool.Queued(),
			Accepted:   pool.Accepted.Load(),
			Shed:       pool.Shed.Load(),
			Expired:    pool.Expired.Load(),
		}

		io := map[string]flow.Flow{"inspect": pool.IO()}

		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}

		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)
		msg.Version, msg.Revision = version, revision

		if hash, rev, apply, names := applied.Snapshot(); apply != "" {
			msg.ConfigHash = hash
			msg.Rev = rev
			msg.Apply = apply
			msg.Profiles = names
		} else {
			msg.Profiles = store.Current().Names()
		}

		if err := pulse.Publish(nc, msg); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
		}
	}

	beat()

	tick := time.NewTicker(cfg.HeartbeatEvery)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
}

func waitForSignal(log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	sig := <-ch
	log.Info("draining", "signal", sig.String())
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

/*
 * bodyLoader -- обменник объектов для условий по заголовкам, кукам и
 * аргументам. Без него условия по ним считают объект недоступным, а поля
 * сообщения и vars работают как прежде: ошибкой старта отсутствие адреса не
 * делается, контур поднимается по частям, -- но предупреждение громкое.
 */
func bodyLoader(cfg *config.Config, log *slog.Logger) (*body.Loader, func(), error) {
	if cfg.RedisURL == "" {
		log.Warn("object store is not configured",
			"detail", "REDIS_URL is empty: conditions on headers, cookies and args see no objects")

		return body.NewLoader(nil, nil), func() {}, nil
	}

	store, err := body.NewRedisStore(cfg.RedisURL, config.RedisTimeout)
	if err != nil {
		return nil, nil, err
	}

	// Недостижимое хранилище -- ошибка старта, а не сюрприз на первом условии.
	if err := store.Ping(context.Background()); err != nil {
		return nil, nil, err
	}

	log.Info("object store connected", "driver", "redis")

	return body.NewLoader(store, nil), func() { _ = store.Close() }, nil
}
