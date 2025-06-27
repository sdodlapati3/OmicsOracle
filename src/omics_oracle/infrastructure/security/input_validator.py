"""
Input Validation and Sanitization

Provides comprehensive input validation and sanitization:
- Type validation and conversion
- String sanitization and escaping
- Custom validation rules
- Security-focused input processing
"""

import html
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Pattern, Union

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of input validation."""

    is_valid: bool
    value: Any = None
    errors: List[str] = None
    sanitized_value: Any = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class ValidationRule(ABC):
    """Abstract base class for validation rules."""

    @abstractmethod
    def validate(self, value: Any) -> ValidationResult:
        """Validate the input value."""
        pass


class TypeValidationRule(ValidationRule):
    """Validates input type."""

    def __init__(self, expected_type: type, allow_none: bool = False):
        self.expected_type = expected_type
        self.allow_none = allow_none

    def validate(self, value: Any) -> ValidationResult:
        """Validate type."""
        if value is None and self.allow_none:
            return ValidationResult(True, None, [], None)

        if not isinstance(value, self.expected_type):
            return ValidationResult(
                False,
                value,
                [
                    f"Expected {self.expected_type.__name__}, got {type(value).__name__}"
                ],
            )

        return ValidationResult(True, value, [], value)


class StringLengthRule(ValidationRule):
    """Validates string length."""

    def __init__(self, min_length: int = 0, max_length: Optional[int] = None):
        self.min_length = min_length
        self.max_length = max_length

    def validate(self, value: Any) -> ValidationResult:
        """Validate string length."""
        if not isinstance(value, str):
            return ValidationResult(False, value, ["Value must be a string"])

        length = len(value)
        errors = []

        if length < self.min_length:
            errors.append(
                f"String too short (minimum {self.min_length} characters)"
            )

        if self.max_length and length > self.max_length:
            errors.append(
                f"String too long (maximum {self.max_length} characters)"
            )

        is_valid = len(errors) == 0
        return ValidationResult(
            is_valid, value, errors, value if is_valid else None
        )


class RegexValidationRule(ValidationRule):
    """Validates input against regex pattern."""

    def __init__(
        self,
        pattern: Union[str, Pattern],
        error_message: str = "Invalid format",
    ):
        self.pattern = (
            re.compile(pattern) if isinstance(pattern, str) else pattern
        )
        self.error_message = error_message

    def validate(self, value: Any) -> ValidationResult:
        """Validate against regex pattern."""
        if not isinstance(value, str):
            return ValidationResult(False, value, ["Value must be a string"])

        if not self.pattern.match(value):
            return ValidationResult(False, value, [self.error_message])

        return ValidationResult(True, value, [], value)


class NumericRangeRule(ValidationRule):
    """Validates numeric values are within range."""

    def __init__(
        self,
        min_value: Optional[Union[int, float]] = None,
        max_value: Optional[Union[int, float]] = None,
    ):
        self.min_value = min_value
        self.max_value = max_value

    def validate(self, value: Any) -> ValidationResult:
        """Validate numeric range."""
        if not isinstance(value, (int, float)):
            return ValidationResult(False, value, ["Value must be numeric"])

        errors = []

        if self.min_value is not None and value < self.min_value:
            errors.append(f"Value too small (minimum {self.min_value})")

        if self.max_value is not None and value > self.max_value:
            errors.append(f"Value too large (maximum {self.max_value})")

        is_valid = len(errors) == 0
        return ValidationResult(
            is_valid, value, errors, value if is_valid else None
        )


class InputValidator:
    """Comprehensive input validation and sanitization system."""

    def __init__(self):
        self._field_rules: Dict[str, List[ValidationRule]] = {}

    def add_rule(self, field_name: str, rule: ValidationRule) -> None:
        """Add validation rule for a field."""
        if field_name not in self._field_rules:
            self._field_rules[field_name] = []
        self._field_rules[field_name].append(rule)

    def validate_field(self, field_name: str, value: Any) -> ValidationResult:
        """Validate a single field."""
        if field_name not in self._field_rules:
            return ValidationResult(True, value, [], value)

        for rule in self._field_rules[field_name]:
            result = rule.validate(value)
            if not result.is_valid:
                return result

        return ValidationResult(True, value, [], value)

    def validate_dict(
        self, data: Dict[str, Any]
    ) -> Dict[str, ValidationResult]:
        """Validate a dictionary of field values."""
        results = {}

        for field_name, value in data.items():
            results[field_name] = self.validate_field(field_name, value)

        return results

    def is_valid_dict(self, data: Dict[str, Any]) -> bool:
        """Check if all fields in dictionary are valid."""
        results = self.validate_dict(data)
        return all(result.is_valid for result in results.values())

    @staticmethod
    def sanitize_string(
        value: str,
        html_escape: bool = True,
        strip_whitespace: bool = True,
        max_length: Optional[int] = None,
    ) -> str:
        """Sanitize string input."""
        if not isinstance(value, str):
            value = str(value)

        if strip_whitespace:
            value = value.strip()

        if html_escape:
            value = html.escape(value)

        if max_length and len(value) > max_length:
            value = value[:max_length]

        return value

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe filesystem operations."""
        # Remove or replace dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', "_", filename)

        # Remove control characters
        filename = "".join(char for char in filename if ord(char) >= 32)

        # Limit length
        if len(filename) > 255:
            name, ext = (
                filename.rsplit(".", 1) if "." in filename else (filename, "")
            )
            max_name_length = 255 - len(ext) - 1
            filename = name[:max_name_length] + ("." + ext if ext else "")

        return filename

    @staticmethod
    def validate_email(email: str) -> bool:
        """Basic email validation."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_url(url: str) -> bool:
        """Basic URL validation."""
        pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(pattern, url))


# Pre-configured validators for common use cases
def create_string_validator(
    min_length: int = 0, max_length: Optional[int] = None
) -> InputValidator:
    """Create validator for string fields."""
    validator = InputValidator()
    validator.add_rule("value", TypeValidationRule(str))
    validator.add_rule("value", StringLengthRule(min_length, max_length))
    return validator


def create_email_validator() -> InputValidator:
    """Create validator for email fields."""
    validator = InputValidator()
    validator.add_rule("email", TypeValidationRule(str))
    validator.add_rule(
        "email",
        RegexValidationRule(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "Invalid email format",
        ),
    )
    return validator


def create_numeric_validator(
    min_value: Optional[Union[int, float]] = None,
    max_value: Optional[Union[int, float]] = None,
) -> InputValidator:
    """Create validator for numeric fields."""
    validator = InputValidator()
    validator.add_rule("value", TypeValidationRule((int, float)))
    validator.add_rule("value", NumericRangeRule(min_value, max_value))
    return validator
