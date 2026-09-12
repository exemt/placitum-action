/*
 * Куда уходит журнал самого процесса.
 *
 * Имена без имени инспектора: настройка одна на весь контур, как
 * WAF_HEARTBEAT_EVERY, и разводить её по WAF_IP_*, WAF_MODSEC_* значило бы
 * заводить пять способов выключить одно и то же. Уровень журнала при этом
 * остаётся своим (WAF_<имя>_LOG): его крутят одному процессу, а не флоту.
 */

package config

import (
	"os"
	"strings"
)

/*
 * LogShip — уезжает ли журнал процесса на шину. По умолчанию да: процесс,
 * чьи ошибки видны только в docker логах его контейнера, на контуре из
 * десятка машин не виден никому.
 *
 * off оставляет только stdout. Это законный режим для машины, где журнал
 * собирает кто-то другой, и он же — первое, что выключают, когда разбирают
 * саму доставку.
 */
func LogShip() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAF_LOG_SHIP"))) {
	case "off", "0", "no", "false":
		return false
	default:
		return true
	}
}

/*
 * LogWriter — чем подписан журнал в waf.log: колонка writer, первый фильтр
 * строки. По умолчанию имя машины, то же, что уходит в кадре присутствия, —
 * по нему строка журнала и кадр флота сходятся на один процесс.
 *
 * fallback — имя инспектора: в окружении без hostname (редкость, но не
 * ошибка) писатель всё равно обязан называться, иначе строки соберутся в
 * общую кучу «unknown».
 */
func LogWriter(fallback string) string {
	if v := strings.TrimSpace(os.Getenv("WAF_LOG_WRITER")); v != "" {
		return v
	}

	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}

	return fallback
}
