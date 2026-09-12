/*
 * Проба: публикует сообщение инспекции на subject и ждёт вердикт.
 *
 * Проба идёт тем же путём, что и настоящий запрос от модуля, и в этом её смысл
 * как healthcheck: если вердикт вернулся, значит живы соединение с шиной,
 * подписка, загруженные профили и пул воркеров.
 * TCP-пинг до NATS не сказал бы ни про одно из этого.
 *
 * Профиля _probe у инспектора нет: проба идёт с профилем default, который
 * поставка не даёт удалить, и принимает любой вердикт -- в том числе error.
 * Вердикт вернулся -- значит живы соединение с шиной, подписка и пул
 * воркеров; что именно ответил инспектор, дело профиля, а не здоровья.
 *
 *     action-probe
 *     action-probe --profile shop --uri /api/orders --expect allow
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/protocol"
)

func main() {
	var (
		servers = flag.String("servers", env("NATS_URL", "nats://127.0.0.1:4222"),
			"адреса шины через запятую")
		subject = flag.String("subject", env("WAF_ACTION_SUBJECT", "waf.req.action"),
			"subject инспектора")
		name = flag.String("inspector", env("WAF_ACTION_NAME", "action"),
			"имя инспектора в сообщении")
		profile = flag.String("profile", "default", "значение route.profile")
		uri     = flag.String("uri", "/healthcheck", "путь запроса, можно со строкой запроса")
		method  = flag.String("method", "GET", "метод запроса")
		phase   = flag.String("phase", protocol.PhaseRequest, "фаза: request или response")
		status  = flag.Int("status", 200, "код ответа для фазы response")
		expect  = flag.String("expect", "",
			"ожидаемый вердикт: allow, score, redirect, deny; пусто -- любой")
		timeout = flag.Duration("timeout", time.Second, "сколько ждать ответа")
		quiet   = flag.Bool("quiet", false, "не печатать ответ, только код возврата")
	)

	flag.Parse()

	if err := run(*servers, *subject, *name, *profile, *uri, *method, *phase,
		*expect, *status, *timeout, *quiet); err != nil {

		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func run(servers, subject, name, profile, uri, method, phase, expect string,
	status int, timeout time.Duration, quiet bool) error {

	nc, err := nats.Connect(servers, nats.Timeout(timeout), nats.NoReconnect())
	if err != nil {
		return err
	}

	defer nc.Close()

	payload, err := json.Marshal(request(name, profile, uri, method, phase, status, timeout))
	if err != nil {
		return err
	}

	msg, err := nc.Request(subject, payload, timeout)
	if err != nil {
		return fmt.Errorf("no verdict from %s: %w", subject, err)
	}

	var reply protocol.Reply

	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("malformed reply: %w", err)
	}

	if !quiet {
		out, _ := json.Marshal(reply)
		fmt.Println(string(out))
	}

	if expect != "" && reply.Verdict != expect {
		return fmt.Errorf("verdict is %q, expected %q", reply.Verdict, expect)
	}

	return nil
}

func request(name, profile, uri, method, phase string, status int,
	timeout time.Duration) *protocol.Request {

	path, args, _ := strings.Cut(uri, "?")

	req := &protocol.Request{
		V:          protocol.Version,
		RID:        fmt.Sprintf("%016x", time.Now().UnixNano()),
		Phase:      phase,
		Inspector:  name,
		DeadlineMS: int(timeout.Milliseconds()),
		Node:       "probe",
		Conn: protocol.Conn{
			ClientIP:   "127.0.0.1",
			ClientPort: 12345,
			ServerIP:   "127.0.0.1",
			ServerPort: 8080,
		},
		HTTP: protocol.HTTP{
			Method:   method,
			Scheme:   "http",
			Host:     "probe.local",
			URI:      path,
			ArgsSize: int64(len(args)),
			Version:  "HTTP/1.1",
		},
		/*
		 * Заявки на объекты обменника нет: пробе нечего в него класть, а
		 * needs, которому нечем ответить, ввёл бы инспектора в заблуждение --
		 * он решил бы, что тело просто не приехало.
		 */
		Route: protocol.Route{ServerName: "probe.local", Location: "/", Profile: profile},
		Score: protocol.ScoreState{DenyAt: 100},
	}

	if phase == protocol.PhaseResponse {
		req.Response = &protocol.Response{Status: status}
	}

	return req
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}
