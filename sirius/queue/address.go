package queue

import (
	"os"
	"strings"
)

func rabbitMQAddress() string {
	if address := strings.TrimSpace(os.Getenv("RABBITMQ_URL")); address != "" {
		return address
	}
	return SIRIUS_RABBITMQ
}
