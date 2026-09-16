"""Asynchronous convenience API over the same cancellable lifecycle."""
import asyncio

from .engine import review
from .runtime import CancellationToken


async def review_async(request, backend=None, validator=None, **options):
    token = options.pop("cancellation", None) or CancellationToken()
    task = asyncio.create_task(asyncio.to_thread(review, request, backend, validator,
                                                cancellation=token, **options))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        token.cancel()
        # The underlying engine finalizes its cancelled report and owned resources.
        return await asyncio.shield(task)
