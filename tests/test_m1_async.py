import asyncio
import threading
import time

from test_standalone import history, FakeBackend
from security_review import ReviewRequest, review_async
from security_review.runtime import checkpoint


def test_async_cancellation_waits_for_report_cleanup(history):
    started = threading.Event()
    class Cooperative(FakeBackend):
        def investigate(self, *args):
            started.set()
            while True:
                checkpoint()
                time.sleep(0.01)
    async def run():
        task = asyncio.create_task(review_async(ReviewRequest(*history), Cooperative()))
        while not started.is_set() and not task.done():
            await asyncio.sleep(0.01)
        task.cancel()
        return await task
    report = asyncio.run(run())
    assert report.status == "cancelled"
    assert report.events[-1]["state"] == "cancelled"
