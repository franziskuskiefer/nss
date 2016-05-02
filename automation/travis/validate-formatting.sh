#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

STATUS=0
for i in $(find $1 -type f -name '*.[ch]' -print); do
  if ! clang-format-3.8 $i | diff $i -; then
    echo "Sorry, $i is not formatted properly. Please use clang-format 3.8 on your patch before landing."
    STATUS=1
  fi
done
exit $STATUS
