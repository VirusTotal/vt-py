# Copyright © 2019 The vt-py authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import asyncio


def make_sync(future):
  """Utility function that waits for an async call, making it sync."""
  try:
    event_loop = asyncio.get_event_loop()
  except RuntimeError:
    # Generate an event loop if there isn't any.
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
  return event_loop.run_until_complete(future)
