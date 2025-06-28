"""
API Versioning Framework for OmicsOracle
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import semver
from fastapi import HTTPException, Request, Response


class VersionStatus(Enum):
    """API version status"""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUNSET = "sunset"
    BETA = "beta"
    ALPHA = "alpha"


class VersioningStrategy(Enum):
    """API versioning strategies"""

    URL_PATH = "url_path"  # /api/v1/search
    HEADER = "header"  # X-API-Version: 1.0
    QUERY_PARAMETER = "query"  # ?version=1.0
    MEDIA_TYPE = "media_type"  # Accept: application/vnd.api+json;version=1


@dataclass
class APIVersion:
    """API version information"""

    version: str
    status: VersionStatus
    release_date: date
    sunset_date: Optional[date] = None
    deprecation_date: Optional[date] = None
    description: str = ""
    changelog: List[str] = field(default_factory=list)
    breaking_changes: List[str] = field(default_factory=list)

    # Compatibility
    backward_compatible_with: List[str] = field(default_factory=list)
    forward_compatible_with: List[str] = field(default_factory=list)

    # Feature flags
    features: Dict[str, bool] = field(default_factory=dict)

    def __post_init__(self):
        # Validate semver
        try:
            semver.VersionInfo.parse(self.version)
        except ValueError:
            raise ValueError(f"Invalid semantic version: {self.version}")

    def is_compatible_with(self, other_version: str) -> bool:
        """Check if this version is compatible with another"""
        return other_version in self.backward_compatible_with or other_version in self.forward_compatible_with

    def is_deprecated(self) -> bool:
        """Check if version is deprecated"""
        return self.status == VersionStatus.DEPRECATED

    def is_sunset(self) -> bool:
        """Check if version is sunset"""
        return self.status == VersionStatus.SUNSET

    def days_until_sunset(self) -> Optional[int]:
        """Calculate days until sunset"""
        if not self.sunset_date:
            return None

        days = (self.sunset_date - date.today()).days
        return max(0, days)


class VersionRegistry:
    """
    Registry for managing API versions
    """

    def __init__(self):
        self._versions: Dict[str, APIVersion] = {}
        self._default_version: Optional[str] = None
        self._latest_version: Optional[str] = None

        # Version aliases
        self._aliases: Dict[str, str] = {}  # alias -> version

        self.logger = logging.getLogger(__name__)

    def register_version(self, version: APIVersion):
        """Register a new API version"""
        self._versions[version.version] = version

        # Update latest version
        if not self._latest_version or self._is_newer(version.version, self._latest_version):
            self._latest_version = version.version

        # Set as default if it's the first active version
        if not self._default_version and version.status == VersionStatus.ACTIVE:
            self._default_version = version.version

        self.logger.info(f"Registered API version: {version.version} ({version.status.value})")

    def register_alias(self, alias: str, version: str):
        """Register an alias for a version"""
        if version not in self._versions:
            raise ValueError(f"Version {version} not registered")

        self._aliases[alias] = version
        self.logger.info(f"Registered alias '{alias}' for version {version}")

    def get_version(self, version_identifier: str) -> Optional[APIVersion]:
        """Get version by identifier (version or alias)"""
        # Check aliases first
        if version_identifier in self._aliases:
            version_identifier = self._aliases[version_identifier]

        return self._versions.get(version_identifier)

    def get_default_version(self) -> Optional[APIVersion]:
        """Get default version"""
        if self._default_version:
            return self._versions.get(self._default_version)
        return None

    def get_latest_version(self) -> Optional[APIVersion]:
        """Get latest version"""
        if self._latest_version:
            return self._versions.get(self._latest_version)
        return None

    def get_active_versions(self) -> List[APIVersion]:
        """Get all active versions"""
        return [v for v in self._versions.values() if v.status == VersionStatus.ACTIVE]

    def get_supported_versions(self) -> List[APIVersion]:
        """Get all supported versions (active + deprecated, not sunset)"""
        return [
            v for v in self._versions.values() if v.status in [VersionStatus.ACTIVE, VersionStatus.DEPRECATED]
        ]

    def list_versions(self) -> List[str]:
        """List all registered version strings"""
        return sorted(self._versions.keys(), key=lambda v: semver.VersionInfo.parse(v))

    def is_supported(self, version: str) -> bool:
        """Check if version is supported"""
        version_info = self.get_version(version)
        return version_info is not None and not version_info.is_sunset()

    def deprecate_version(self, version: str, sunset_date: Optional[date] = None):
        """Mark version as deprecated"""
        if version in self._versions:
            self._versions[version].status = VersionStatus.DEPRECATED
            if sunset_date:
                self._versions[version].sunset_date = sunset_date

            self.logger.info(f"Version {version} marked as deprecated")

    def sunset_version(self, version: str):
        """Mark version as sunset"""
        if version in self._versions:
            self._versions[version].status = VersionStatus.SUNSET
            self.logger.info(f"Version {version} marked as sunset")

    def _is_newer(self, version1: str, version2: str) -> bool:
        """Check if version1 is newer than version2"""
        try:
            v1 = semver.VersionInfo.parse(version1)
            v2 = semver.VersionInfo.parse(version2)
            return v1 > v2
        except (ValueError, TypeError):
            return False


class VersionDetector:
    """
    Detect API version from request
    """

    def __init__(
        self,
        strategy: VersioningStrategy = VersioningStrategy.URL_PATH,
        header_name: str = "X-API-Version",
        query_param: str = "version",
        path_pattern: str = r"/api/v(\d+(?:\.\d+)*)/",
        media_type_pattern: str = r"version=(\d+(?:\.\d+)*)",
    ):
        self.strategy = strategy
        self.header_name = header_name
        self.query_param = query_param
        self.path_pattern = re.compile(path_pattern)
        self.media_type_pattern = re.compile(media_type_pattern)

        self.logger = logging.getLogger(__name__)

    def detect_version(self, request: Request) -> Optional[str]:
        """Detect version from request"""

        if self.strategy == VersioningStrategy.URL_PATH:
            return self._detect_from_path(request)

        elif self.strategy == VersioningStrategy.HEADER:
            return self._detect_from_header(request)

        elif self.strategy == VersioningStrategy.QUERY_PARAMETER:
            return self._detect_from_query(request)

        elif self.strategy == VersioningStrategy.MEDIA_TYPE:
            return self._detect_from_media_type(request)

        return None

    def _detect_from_path(self, request: Request) -> Optional[str]:
        """Detect version from URL path"""
        match = self.path_pattern.search(str(request.url.path))
        return match.group(1) if match else None

    def _detect_from_header(self, request: Request) -> Optional[str]:
        """Detect version from header"""
        return request.headers.get(self.header_name)

    def _detect_from_query(self, request: Request) -> Optional[str]:
        """Detect version from query parameter"""
        return request.query_params.get(self.query_param)

    def _detect_from_media_type(self, request: Request) -> Optional[str]:
        """Detect version from Accept header media type"""
        accept_header = request.headers.get("Accept", "")
        match = self.media_type_pattern.search(accept_header)
        return match.group(1) if match else None


class VersionManager:
    """
    Main version management coordinator
    """

    def __init__(
        self,
        versioning_strategy: VersioningStrategy = VersioningStrategy.URL_PATH,
        default_version: str = "1.0.0",
    ):
        self.registry = VersionRegistry()
        self.detector = VersionDetector(strategy=versioning_strategy)
        self.default_version = default_version

        # Middleware callbacks
        self._request_processors: List[Callable] = []
        self._response_processors: List[Callable] = []

        # Version-specific transformers
        self._request_transformers: Dict[str, List[Callable]] = {}
        self._response_transformers: Dict[str, List[Callable]] = {}

        # Migration handlers
        self._migration_handlers: Dict[str, Callable] = {}  # from_version -> handler

        self.logger = logging.getLogger(__name__)

    def initialize_versions(self):
        """Initialize default API versions"""

        # Version 1.0.0 - Initial release
        v1 = APIVersion(
            version="1.0.0",
            status=VersionStatus.ACTIVE,
            release_date=date(2024, 1, 1),
            description="Initial API release with basic search functionality",
            features={
                "basic_search": True,
                "ai_summarization": True,
                "realtime_updates": False,
                "advanced_filtering": False,
            },
        )
        self.registry.register_version(v1)

        # Version 1.1.0 - Real-time updates
        v1_1 = APIVersion(
            version="1.1.0",
            status=VersionStatus.ACTIVE,
            release_date=date(2024, 6, 1),
            description="Added real-time search updates via WebSocket",
            changelog=[
                "Added WebSocket support for real-time updates",
                "Enhanced error handling and responses",
                "Improved search performance",
            ],
            features={
                "basic_search": True,
                "ai_summarization": True,
                "realtime_updates": True,
                "advanced_filtering": False,
            },
            backward_compatible_with=["1.0.0"],
        )
        self.registry.register_version(v1_1)

        # Version 2.0.0 - Advanced features with breaking changes
        v2 = APIVersion(
            version="2.0.0",
            status=VersionStatus.BETA,
            release_date=date(2024, 12, 1),
            description="Major release with advanced filtering and breaking changes",
            changelog=[
                "Advanced search filtering capabilities",
                "New response format for search results",
                "Enhanced metadata in responses",
                "Improved caching system",
            ],
            breaking_changes=[
                "Changed search response format",
                "Renamed some API endpoints",
                "Updated error response structure",
            ],
            features={
                "basic_search": True,
                "ai_summarization": True,
                "realtime_updates": True,
                "advanced_filtering": True,
                "batch_operations": True,
            },
        )
        self.registry.register_version(v2)

        # Register aliases
        self.registry.register_alias("latest", "2.0.0")
        self.registry.register_alias("stable", "1.1.0")
        self.registry.register_alias("v1", "1.1.0")
        self.registry.register_alias("v2", "2.0.0")

    def resolve_version(self, request: Request) -> APIVersion:
        """Resolve API version for request"""

        # Detect version from request
        version_str = self.detector.detect_version(request)

        # Use default if not detected
        if not version_str:
            version_str = self.default_version

        # Get version info
        version_info = self.registry.get_version(version_str)

        # Fallback to default if version not found
        if not version_info:
            self.logger.warning(f"Unknown API version requested: {version_str}, using default")
            version_info = self.registry.get_version(self.default_version)

        # Check if version is supported
        if version_info and version_info.is_sunset():
            raise HTTPException(
                status_code=410,
                detail=f"API version {version_str} is no longer supported",
            )

        return version_info

    def add_version_headers(self, response: Response, version: APIVersion):
        """Add version-related headers to response"""

        response.headers["X-API-Version"] = version.version
        response.headers["X-API-Version-Status"] = version.status.value

        # Deprecation warning
        if version.is_deprecated():
            response.headers["Warning"] = f'199 - "API version {version.version} is deprecated"'

            if version.sunset_date:
                response.headers["Sunset"] = version.sunset_date.isoformat()

        # Available versions
        supported_versions = [v.version for v in self.registry.get_supported_versions()]
        response.headers["X-API-Supported-Versions"] = ",".join(supported_versions)

    def register_request_transformer(self, version: str, transformer: Callable):
        """Register request transformer for specific version"""
        if version not in self._request_transformers:
            self._request_transformers[version] = []

        self._request_transformers[version].append(transformer)

    def register_response_transformer(self, version: str, transformer: Callable):
        """Register response transformer for specific version"""
        if version not in self._response_transformers:
            self._response_transformers[version] = []

        self._response_transformers[version].append(transformer)

    def register_migration_handler(self, from_version: str, handler: Callable):
        """Register migration handler for version upgrade/downgrade"""
        self._migration_handlers[from_version] = handler

    async def transform_request(self, request: Request, version: APIVersion) -> Request:
        """Transform request based on version"""

        transformers = self._request_transformers.get(version.version, [])

        for transformer in transformers:
            try:
                request = await transformer(request, version)
            except Exception as e:
                self.logger.error(f"Request transformation error for version {version.version}: {e}")

        return request

    async def transform_response(self, response: Any, version: APIVersion) -> Any:
        """Transform response based on version"""

        transformers = self._response_transformers.get(version.version, [])

        for transformer in transformers:
            try:
                response = await transformer(response, version)
            except Exception as e:
                self.logger.error(f"Response transformation error for version {version.version}: {e}")

        return response

    def get_version_info(self) -> Dict[str, Any]:
        """Get version information for API documentation"""

        versions_info = []

        for version in self.registry.get_supported_versions():
            version_data = {
                "version": version.version,
                "status": version.status.value,
                "release_date": version.release_date.isoformat(),
                "description": version.description,
                "features": version.features,
            }

            if version.is_deprecated():
                version_data["deprecated"] = True
                if version.sunset_date:
                    version_data["sunset_date"] = version.sunset_date.isoformat()
                    version_data["days_until_sunset"] = version.days_until_sunset()

            if version.changelog:
                version_data["changelog"] = version.changelog

            if version.breaking_changes:
                version_data["breaking_changes"] = version.breaking_changes

            versions_info.append(version_data)

        return {
            "default_version": self.default_version,
            "latest_version": self.registry.get_latest_version().version
            if self.registry.get_latest_version()
            else None,
            "versioning_strategy": self.detector.strategy.value,
            "versions": versions_info,
        }


# Global version manager instance
version_manager = VersionManager()
