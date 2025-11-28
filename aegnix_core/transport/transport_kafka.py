# aegnix_ae/transport/transport_kafka.py
import logging
# from aegnix_ae.transport.transport_base import BaseTransport
from aegnix_core.transport.transport_base import BaseTransport

log = logging.getLogger(__name__)



class KafkaAdapter(BaseTransport):
    def __init__(self, brokers="localhost:9092", mock=True):
        self.mock = mock
        self.handlers = {}
        self.brokers = brokers
        if self.mock:
            log.warning("[KAFKA] mock mode")
        else:
            # from kafka import KafkaProducer, KafkaConsumer
            # self.producer = KafkaProducer(bootstrap_servers=self.brokers)
            # self.consumers = {}
            pass

    def publish(self, subject, message):
        if self.mock:
            log.info(f"[KAFKA-MOCK PUB] {subject}: {str(message)[:60]}...")
            if subject in self.handlers:
                for h in self.handlers[subject]:
                    h(message)
            return
        # self.producer.send(subject, json.dumps(message).encode("utf-8"))

    def subscribe(self, subject, handler):
        if self.mock:
            self.handlers.setdefault(subject, []).append(handler)
            log.info(f"[KAFKA-MOCK SUB] {subject}")
            return
        # real consumer wiring here
