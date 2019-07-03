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

import trio
import vt


c = vt.Client('744adb7d697fea35d98019aa66bb5693aa84fae0a0b842e9a900892a760047cc')

async def print_comments():
  async for comment in c.iterator('/comments', batch_size=5, limit=2):
    print(comment.id)


async def print_files():
  async for f in c.feed('files',  cursor='201906061401'):
    print(f.id)

trio.run(print_comments)
