#!/usr/local/bin/python
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

"""Console 1-click tool to download files from VT.

It could be extremely handy to malware analysts in their day-to-day job.

Setup:
1) Put script in your Path directory and set execution permission
   if needed (chmod 755).
2) Set VT_API_KEY environment variable, note that download file permission
   is needed.
3) You might want to rename it to single character for quick access
   ("g.py" -> "g").

Usage:
1) g 44d88612fea8a8f36de82e1278abb02f - will download file with this hash to
   your current working directory (CWD).
MD5, SHA1, SHA256 - supported file checksums.

2) g 123.txt - will read list of hashes from 123.txt file, one per line and
   download them in CWD.
"""

import argparse
import logging
import os
import vt


API_KEY_ENV_VAR = "VT_API_KEY"
SUPPORTED_CHECKSUM_LENS = (32, 40, 64)

logging.basicConfig(format="%(message)s", level=logging.INFO)


def download_from_vt(file_id):
  if len(file_id) not in SUPPORTED_CHECKSUM_LENS:
    logging.warning("Unsupported checksum length - %d", len(file_id))
    return

  with open(file_id, "wb") as f:
    try:
      with vt.Client(os.environ.get(API_KEY_ENV_VAR)) as vt_client:
        vt_client.download_file(file_id, f)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.error(
          "Exception while downloading file with a hash %s: %s", file_id, e
      )
    else:
      logging.info("Successfully downloaded %s", file_id)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "user_input",
      help=(
          "File checksum (SHA-256, SHA-1, MD5) or text file containing "
          "list of checksums"
      ),
  )
  args = parser.parse_args()

  if os.environ.get(API_KEY_ENV_VAR) is None:
    logging.critical("Please set %s environment variable", API_KEY_ENV_VAR)
    return

  if os.path.isfile(args.user_input):
    logging.info("Treating input as a file, going to extract hashes...")
    with open(args.user_input, encoding="utf-8") as f:
      for line in f:
        download_from_vt(file_id=line.rstrip())

  else:
    logging.info("Treating input as a checksum...")
    download_from_vt(file_id=args.user_input)


if __name__ == "__main__":
  main()
