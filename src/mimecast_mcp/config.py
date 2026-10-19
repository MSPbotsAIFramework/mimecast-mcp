# Copyright 2026 MSPbots.ai
#
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
"""Process settings and API gateway hosts. Holds no credentials: those arrive per request as headers."""

import re

from pydantic_settings import BaseSettings, SettingsConfigDict

GLOBAL_HOST = "api.services.mimecast.com"
# Mimecast API 2.0 gateways: the global one fails over between regions; the
# instance ones keep traffic in that region (no failover).
INSTANCE_HOSTS = {
    "us": "us-api.services.mimecast.com",
    "uk": "uk-api.services.mimecast.com",
    "de": "de-api.services.mimecast.com",
}
# Region codes of the older API 1.0 (and of earlier versions of this server) all
# map to the global gateway, which serves every account.
LEGACY_REGIONS = {"global", "us", "eu", "de", "uk", "ca", "za", "au", "offshore", "je", "sandbox"}

MAX_PAGE_SIZE = 100

_HOST = re.compile(r"^(?:(us|uk|de)-)?api\.services\.mimecast\.com$")
_INSTANCE = re.compile(r"^(us|uk|de)-api(?:-instance)?$")


class Settings(BaseSettings):
    # extra="ignore": the runtime injects variables this project does not declare.
    model_config = SettingsConfigDict(extra="ignore")

    mcp_http_port: int = 8080
    mcp_http_host: str = "0.0.0.0"
    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()


def normalize_region(value: str | None) -> str | None:
    """The API host for an X-Mimecast-Region value, or None when it is not recognised.

    Empty or a region code (us, eu, uk, de, ca, za, au, ...) -> the global gateway;
    us-api / uk-api / de-api or a full *.services.mimecast.com host -> that gateway.
    """
    text = (value or "").strip().lower()
    text = re.sub(r"^https?://", "", text).split("/")[0]
    if not text or text in LEGACY_REGIONS:
        return GLOBAL_HOST
    match = _INSTANCE.match(text)
    if match:
        return INSTANCE_HOSTS[match.group(1)]
    if _HOST.match(text):
        return text
    return None
