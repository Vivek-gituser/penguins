class MockInbox:
    """Simulated delivery only. Never sends real email."""
    def deliver(self, message, recipient):
        return {
            "status": "SIMULATED_DELIVERY",
            "recipient": recipient,
            "message": message
        }
