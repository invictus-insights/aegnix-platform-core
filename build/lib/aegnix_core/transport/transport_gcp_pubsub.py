import logging, os
# from aegnix_ae.transport.transport_base import BaseTransport
from aegnix_core.transport.transport_base import BaseTransport

try:
    from google.cloud import pubsub_v1
except ImportError:
    pubsub_v1 = None

log = logging.getLogger(__name__)


class GcpPubSubAdapter(BaseTransport):
    """GCP Pub/Sub adapter with safe local fallback."""

    def __init__(self, project_id=None):
        self.project_id = project_id or os.getenv("GCP_PROJECT", "aegnix-dev")
        self.mock_mode = False
        self.publisher = None
        self.subscriber = None

        # Detect credentials
        creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not creds or not os.path.exists(creds):
            self.mock_mode = True
            log.warning("[GCP PUBSUB] No credentials found — using mock mode")
            return

        if not pubsub_v1:
            raise ImportError("google-cloud-pubsub not installed")

        try:
            self.publisher = pubsub_v1.PublisherClient()
            self.subscriber = pubsub_v1.SubscriberClient()
            log.info(f"[GCP PUBSUB] Connected to project {self.project_id}")
        except Exception as e:
            self.mock_mode = True
            log.error(f"[GCP PUBSUB] Initialization failed, switching to mock: {e}")

    # ------------------------------------------------------------------
    def publish(self, subject: str, message):
        """Publish message to GCP topic or mock log."""
        if self.mock_mode or not self.publisher:
            log.info(f"[GCP MOCK PUB] {subject}: {str(message)[:60]}...")
            return True

        topic_path = self.publisher.topic_path(self.project_id, subject)
        data = message.encode("utf-8") if isinstance(message, str) else str(message).encode("utf-8")
        future = self.publisher.publish(topic_path, data)
        log.debug(f"[GCP PUBSUB] Published to {topic_path}")
        return future.result()

    # ------------------------------------------------------------------
    def subscribe(self, subject: str, handler):
        """Subscribe to topic and invoke handler for each message."""
        if self.mock_mode or not self.subscriber:
            log.info(f"[GCP MOCK SUB] Subscribed to {subject}")
            return

        sub_name = f"{subject}-sub"
        subscription_path = self.subscriber.subscription_path(self.project_id, sub_name)

        def callback(msg):
            log.debug(f"[GCP PUBSUB] Received message on {subject}")
            try:
                handler(msg.data)
            finally:
                msg.ack()

        self.subscriber.subscribe(subscription_path, callback=callback)
        log.info(f"[GCP PUBSUB] Subscribed to {subscription_path}")