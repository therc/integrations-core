# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import re


def compact_query(query):
    return re.sub(r'\s+', ' ', query.strip())
