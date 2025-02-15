package queue

import (
	"log"
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
		log.Fatalf("%s: %s", msg, err)
	}
}

// Listen listens to a RabbitMQ queue specified by qName and processes messages using the provided messageProcessor function.
func Listen(qName string, messageProcessor MessageProcessor) {
	log.Printf("Listening to queue %s", qName)
	
	conn, err := amqp.Dial(SIRIUS_RABBITMQ)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		qName, // name
		false, // durable
		false, // delete when unused
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

	log.Printf("Sent message to queue %s: %s", qName, message)
	return nil
}