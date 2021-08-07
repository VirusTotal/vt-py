import asyncio


def _make_sync(future):
  """Utility function that waits for an async call, making it sync."""
  try:
    event_loop = asyncio.get_event_loop()
  except RuntimeError:
    # Generate an event loop if there isn't any.
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
  return event_loop.run_until_complete(future)
