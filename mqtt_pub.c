/*
 * This example shows how to publish messages from outside of the Mosquitto
 * network loop.
 */

#include <assert.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static struct mosquitto *mosq;

/* Callback called when the client receives a CONNACK message from the broker.
 */
static void on_connect(struct mosquitto *mosq, void *obj, int reason_code) {
  /* Print out the connection result. mosquitto_connack_string() produces an
   * appropriate string for MQTT v3.x clients, the equivalent for MQTT v5.0
   * clients is mosquitto_reason_string().
   */
  syslog(LOG_INFO, "Houston Connected: %s",
         mosquitto_connack_string(reason_code));
  if (reason_code != 0) {
    /* If the connection fails for any reason, we don't want to keep on
     * retrying in this example, so disconnect. Without this, the client
     * will attempt to reconnect. */
    mosquitto_disconnect(mosq);
    syslog(LOG_WARNING, "Connect Reason code error");
  }

  /* You may wish to set a flag here to indicate to your application that the
   * client is now connected. */
}

/* Callback called when the client knows to the best of its abilities that a
 * PUBLISH has been successfully sent. For QoS 0 this means the message has
 * been completely written to the operating system. For QoS 1 this means we
 * have received a PUBACK from the broker. For QoS 2 this means we have
 * received a PUBCOMP from the broker. */
static void on_publish(struct mosquitto *mosq, void *obj, int mid) {}

/* This function pretends to read some data from a sensor and publish it.*/
int report_to_houston(const char *topic, int qos, const unsigned char *data,
                      size_t length) {
  int temp;
  int rc;

  assert(mosq != NULL);
  assert(topic != NULL);
  assert(data != NULL);

  /* Publish the message
   * mosq - our client instance
   * *mid = NULL - we don't want to know what the message id for this message is
   * topic = "example/temperature" - the topic on which this message will be
   * published payloadlen = strlen(payload) - the length of our payload in bytes
   * payload - the actual payload
   * qos = 2 - publish with QoS 2 for this example
   * retain = false - do not use the retained message feature for this message
   */
  rc = mosquitto_publish(mosq, NULL, topic, length, data, 2, false);
  if (rc != MOSQ_ERR_SUCCESS) {
    syslog(LOG_ERR, "Error publishing: %s", mosquitto_strerror(rc));
    return -1;
  }

  return 0;
}

/* init mqtt */
int mqtt_init(void) {
  int rc;

  /* Required before calling other mosquitto functions */
  mosquitto_lib_init();

  /* Create a new client instance.
   * id = NULL -> ask the broker to generate a client id for us
   * clean session = true -> the broker should remove old sessions when we
   * connect obj = NULL -> we aren't passing any of our private data for
   * callbacks
   */
  mosq = mosquitto_new(NULL, true, NULL);
  if (mosq == NULL) {
    syslog(LOG_ERR, "Error: Out of memory.");
    return -ENOMEM;
  }

  /* Configure callbacks. This should be done before connecting ideally. */
  mosquitto_connect_callback_set(mosq, on_connect);
  mosquitto_publish_callback_set(mosq, on_publish);

  /* Connect to test.mosquitto.org on port 1883, with a keepalive of 60 seconds.
   * This call makes the socket connection only, it does not complete the MQTT
   * CONNECT/CONNACK flow, you should use mosquitto_loop_start() or
   * mosquitto_loop_forever() for processing net traffic. */
  rc = mosquitto_connect(mosq, "192.168.1.1", 1883, 60);
  if (rc != MOSQ_ERR_SUCCESS) {
    mosquitto_destroy(mosq);
    syslog(LOG_ERR, "Error: %s", mosquitto_strerror(rc));
    return -ENOTCONN;
  }

  /* Run the network loop in a background thread, this call returns quickly. */
  rc = mosquitto_loop_start(mosq);
  if (rc != MOSQ_ERR_SUCCESS) {
    mosquitto_destroy(mosq);
    syslog(LOG_ERR, "Error: %s", mosquitto_strerror(rc));
    return -ENOSYS;
  }

  return 0;
}

int
mqtt_deinit(void)
{
  assert(mosq != NULL);

  /* disable auto reconnect */
  mosquitto_disconnect(mosq);

  mosquitto_destroy(mosq);

  mosq = NULL;

  mosquitto_lib_cleanup();
  return 0;
}
