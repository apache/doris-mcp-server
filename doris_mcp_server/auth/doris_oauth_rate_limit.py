#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Small in-memory fixed-window rate limiter for Doris OAuth endpoints."""

import time
from dataclasses import dataclass

from starlette.responses import JSONResponse


@dataclass
class RateLimitDecision:
    allowed: bool
    remaining: int
    reset_at: float


class DorisOAuthRateLimiter:
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = max(1, int(window_seconds))
        self._buckets: dict[tuple[str, str], tuple[int, float]] = {}

    def check(self, bucket: str, key: str, limit: int) -> RateLimitDecision:
        if limit <= 0:
            return RateLimitDecision(False, 0, time.time() + self.window_seconds)

        now = time.time()
        bucket_key = (bucket, key)
        count, reset_at = self._buckets.get(bucket_key, (0, now + self.window_seconds))
        if now >= reset_at:
            count = 0
            reset_at = now + self.window_seconds

        if count >= limit:
            self._buckets[bucket_key] = (count, reset_at)
            return RateLimitDecision(False, 0, reset_at)

        count += 1
        self._buckets[bucket_key] = (count, reset_at)
        return RateLimitDecision(True, max(0, limit - count), reset_at)

    def cleanup(self) -> None:
        now = time.time()
        expired = [key for key, (_, reset_at) in self._buckets.items() if now >= reset_at]
        for key in expired:
            self._buckets.pop(key, None)


def rate_limited_response() -> JSONResponse:
    return JSONResponse({"error": "rate_limited"}, status_code=429)
