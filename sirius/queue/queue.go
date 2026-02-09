package queue

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/streadway/amqp"
)

// MessageProcessor is a type for functions that can process messages.
type MessageProcessor func(msg string)

const (
	SIRIUS_RABBITMQ = "amqp://guest:guest@sirius-rabbitmq:5672/"
)

// failOnError is a helper function to log any errors.
func failOnError(err error, msg string) {
	if err != nil {
		slog.Error(msg, "error", err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

// Listen listens to a RabbitMQ queue specified by qName and processes messages using the provided messageProcessor function.
// WARNING: This function calls log.Fatalf on connection failure, killing the entire process.
// For resilient listening with automatic reconnection, use ListenWithRetry instead.
func Listen(qName string, messageProcessor MessageProcessor) {
	slog.Info("Listening to queue", "queue", qName)

	conn, err := amqp.Dial(SIRIUS_RABBITMQ)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		qName, // name
		false, // durable - match TypeScript
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	failOnError(err, "Failed to declare a queue")

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	// Process messages
	// * Each message is processed in a separate goroutine
	// * The callback function messageProcessor is called for each message
	for msg := range msgs {
		go func(m amqp.Delivery) {
			messageProcessor(string(m.Body))
		}(msg)
	}
}

// ListenWithRetry listens to a RabbitMQ queue with automatic reconnection.
// Unlike Listen, this function does NOT call log.Fatalf on failure. Instead it
// retries the connection with exponential backoff (1s → 30s cap) and
// automatically reconnects if the broker drops the connection.
// The listener stops cleanly when ctx is cancelled.
func ListenWithRetry(ctx context.Context, qName string, messageProcessor MessageProcessor) {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		if ctx.Err() != nil {
			slog.Info("Listener shutting down (context cancelled)", "queue", qName)
			return
		}

		err := listenOnce(ctx, qName, messageProcessor)
		if ctx.Err() != nil {
			// Context cancelled during listen — clean exit
			slog.Info("Listener stopped", "queue", qName)
			return
		}

		if err != nil {
			slog.Warn("Listener error, retrying", "queue", qName, "error", err, "backoff", backoff)
		} else {
			// Channel closed without error (e.g. broker restart) — reset backoff
			slog.Info("Listener disconnected, reconnecting", "queue", qName)
			backoff = time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Exponential backoff
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// listenOnce connects to RabbitMQ, consumes from the given queue, and processes
// messages until the connection drops or ctx is cancelled. Returns an error on
// connection/channel failures; returns nil if the message channel closes cleanly.
func listenOnce(ctx context.Context, qName string, messageProcessor MessageProcessor) error {
	conn, err := amqp.Dial(SIRIUS_RABBITMQ)
	if err != nil {
		return fmt.Errorf("connect to RabbitMQ: %w", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}
	defer ch.Close()

	q, err := ch.QueueDeclare(
		qName, // name
		false, // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return fmt.Errorf("declare queue '%s': %w", qName, err)
	}

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		return fmt.Errorf("register consumer on '%s': %w", qName, err)
	}

	slog.Info("Connected to queue", "queue", qName)

	// Monitor for AMQP connection close events
	connCloseCh := conn.NotifyClose(make(chan *amqp.Error, 1))

	for {
		select {
		case <-ctx.Done():
			return nil
		case amqpErr := <-connCloseCh:
			if amqpErr != nil {
				return fmt.Errorf("connection closed: %s", amqpErr.Error())
			}
			return nil
		case msg, ok := <-msgs:
			if !ok {
				return nil // delivery channel closed
			}
			go messageProcessor(string(msg.Body))
		}
	}
}

// Send sends a message to a RabbitMQ queue specified by qName.
func Send(qName string, message string) error {
	conn, err := amqp.Dial(SIRIUS_RABBITMQ)
	if err != nil {
		return err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	q, err := ch.QueueDeclare(
		qName, // name
		false, // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return err
	}

	err = ch.Publish(
		"",     // exchange
		q.Name, // routing key
		false,  // mandatory
		false,  // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(message),
		})
	if err != nil {
		return err
	}

	slog.Debug("Sent message to queue", "queue", qName)
	return nil
}
