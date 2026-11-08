package queue

import "testing"

func TestRabbitMQAddress(t *testing.T) {
	t.Setenv("RABBITMQ_URL", "")
	if got := rabbitMQAddress(); got != SIRIUS_RABBITMQ {
		t.Fatalf("default address = %q", got)
	}
	t.Setenv("RABBITMQ_URL", " amqp://localhost:15673/ ")
	if got := rabbitMQAddress(); got != "amqp://localhost:15673/" {
		t.Fatalf("configured address = %q", got)
	}
}
