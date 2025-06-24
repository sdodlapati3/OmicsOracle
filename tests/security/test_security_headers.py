#!/usr/bin/env python3
"""
Security Headers and HTTPS Testing for OmicsOracle Web Interface

This module tests security headers, HTTPS configuration, and rate limiting.
"""

import socket
import ssl
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests


class SecurityHeadersTester:
    """Test security headers and HTTPS setup."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize security headers tester."""
        self.base_url = base_url
        self.session = requests.Session()

    def test_security_headers(self) -> Dict[str, Any]:
        """Test presence and validity of important security headers."""
        print("🛡️ Testing security headers...")

        required_headers = {
            "X-Content-Type-Options": ["nosniff"],
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": ["1; mode=block", "0"],
            "Strict-Transport-Security": ["max-age="],
            "Content-Security-Policy": [
                "default-src",
                "script-src",
                "style-src",
            ],
            "Referrer-Policy": [
                "strict-origin-when-cross-origin",
                "no-referrer",
                "same-origin",
            ],
            "Permissions-Policy": ["geolocation=", "microphone=", "camera="],
            "X-Permitted-Cross-Domain-Policies": ["none", "master-only"],
            "Cache-Control": ["no-cache", "no-store", "max-age="],
        }

        try:
            response = self.session.get(f"{self.base_url}/", timeout=10)
            headers = response.headers
        except Exception as e:
            return {"error": f"Failed to fetch headers: {str(e)}"}

        results = {}
        missing_headers = []
        weak_headers = []

        for header, expected_values in required_headers.items():
            if header in headers:
                header_value = headers[header]

                # Check if any expected value is present
                is_valid = any(exp in header_value for exp in expected_values)

                results[header] = {
                    "present": True,
                    "value": header_value,
                    "valid": is_valid,
                    "strength": "strong" if is_valid else "weak",
                }

                if not is_valid:
                    weak_headers.append(header)
            else:
                results[header] = {
                    "present": False,
                    "valid": False,
                    "strength": "missing",
                }
                missing_headers.append(header)

        # Additional security headers check
        additional_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
        ]

        information_disclosure = {}
        for header in additional_headers:
            if header in headers:
                information_disclosure[header] = {
                    "present": True,
                    "value": headers[header],
                    "risk": "medium",  # These headers can reveal server information
                }

        # Calculate security score
        total_headers = len(required_headers)
        present_headers = sum(1 for h in results.values() if h["present"])
        valid_headers = sum(1 for h in results.values() if h["valid"])

        security_score = (valid_headers / total_headers) * 100

        return {
            "header_analysis": results,
            "missing_headers": missing_headers,
            "weak_headers": weak_headers,
            "information_disclosure": information_disclosure,
            "security_score": round(security_score, 1),
            "recommendations": self._generate_header_recommendations(
                results, information_disclosure
            ),
        }

    def _generate_header_recommendations(
        self, results: Dict[str, Any], info_disclosure: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for security headers."""
        recommendations = []

        for header, data in results.items():
            if not data["present"]:
                if header == "Strict-Transport-Security":
                    recommendations.append(
                        f"🔴 Add {header}: max-age=31536000; includeSubDomains"
                    )
                elif header == "Content-Security-Policy":
                    recommendations.append(
                        f"🔴 Add {header}: default-src 'self'; script-src 'self'"
                    )
                elif header == "X-Frame-Options":
                    recommendations.append(f"🟡 Add {header}: DENY")
                else:
                    recommendations.append(f"🟡 Add missing header: {header}")
            elif not data["valid"]:
                recommendations.append(f"🟡 Strengthen {header} configuration")

        for header in info_disclosure:
            recommendations.append(
                f"🔵 Consider removing {header} to reduce information disclosure"
            )

        return recommendations

    def test_https_configuration(self) -> Dict[str, Any]:
        """Test HTTPS setup and SSL/TLS configuration."""
        print("🔐 Testing HTTPS configuration...")

        results = {
            "https_available": False,
            "https_redirect": False,
            "ssl_certificate_valid": False,
            "tls_version": None,
            "cipher_suite": None,
            "hsts_header": False,
            "ssl_errors": [],
        }

        # Test HTTPS availability
        https_url = self.base_url.replace("http://", "https://")

        try:
            response = requests.get(https_url, timeout=10, verify=True)
            results["https_available"] = True
            results["ssl_certificate_valid"] = True

            # Check for HSTS header
            if "Strict-Transport-Security" in response.headers:
                results["hsts_header"] = True

        except requests.exceptions.SSLError as e:
            results["ssl_errors"].append(f"SSL Error: {str(e)}")
        except requests.exceptions.ConnectionError:
            results["ssl_errors"].append("HTTPS not available")
        except Exception as e:
            results["ssl_errors"].append(f"HTTPS test error: {str(e)}")

        # Test HTTP to HTTPS redirect
        if self.base_url.startswith("http://"):
            try:
                response = requests.get(
                    self.base_url, allow_redirects=False, timeout=10
                )

                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get("Location", "")
                    if location.startswith("https://"):
                        results["https_redirect"] = True

            except Exception as e:
                results["ssl_errors"].append(f"Redirect test error: {str(e)}")

        # Test SSL/TLS configuration
        if results["https_available"]:
            try:
                parsed_url = urlparse(https_url)
                hostname = parsed_url.hostname
                port = parsed_url.port or 443

                context = ssl.create_default_context()
                with socket.create_connection(
                    (hostname, port), timeout=10
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=hostname
                    ) as ssock:
                        results["tls_version"] = ssock.version()
                        results["cipher_suite"] = ssock.cipher()

            except Exception as e:
                results["ssl_errors"].append(f"TLS analysis error: {str(e)}")

        # Calculate HTTPS security score
        score_factors = [
            results["https_available"],
            results["https_redirect"],
            results["ssl_certificate_valid"],
            results["hsts_header"],
            results["tls_version"] in ["TLSv1.2", "TLSv1.3"]
            if results["tls_version"]
            else False,
        ]

        https_score = (sum(score_factors) / len(score_factors)) * 100
        results["https_security_score"] = round(https_score, 1)

        return results

    def test_rate_limiting(self) -> Dict[str, Any]:
        """Test rate limiting implementation."""
        print("⏱️ Testing rate limiting...")

        # Test endpoints for rate limiting
        test_endpoints = [
            "/api/search",
            "/api/summarize",
            "/api/status",
            "/",
            "/api/visualization/search-stats",
        ]

        results = {}

        for endpoint in test_endpoints:
            print(f"  Testing rate limiting on {endpoint}...")

            endpoint_results = {
                "total_requests": 0,
                "rate_limited_requests": 0,
                "first_rate_limit_at": None,
                "rate_limit_status_code": None,
                "rate_limit_headers": {},
                "response_times": [],
                "rate_limiting_detected": False,
            }

            # Make rapid requests
            for i in range(50):  # Try 50 rapid requests
                try:
                    start_time = time.time()

                    if endpoint == "/api/search":
                        response = self.session.post(
                            f"{self.base_url}{endpoint}",
                            json={"query": f"test{i}", "max_results": 1},
                            timeout=5,
                        )
                    elif endpoint == "/api/summarize":
                        response = self.session.post(
                            f"{self.base_url}{endpoint}",
                            json={
                                "query": f"test{i}",
                                "max_results": 1,
                                "include_batch_summary": False,
                            },
                            timeout=5,
                        )
                    else:
                        response = self.session.get(
                            f"{self.base_url}{endpoint}", timeout=5
                        )

                    response_time = time.time() - start_time
                    endpoint_results["response_times"].append(response_time)
                    endpoint_results["total_requests"] += 1

                    # Check for rate limiting
                    if response.status_code == 429:  # Too Many Requests
                        endpoint_results["rate_limited_requests"] += 1
                        endpoint_results["rate_limiting_detected"] = True

                        if endpoint_results["first_rate_limit_at"] is None:
                            endpoint_results["first_rate_limit_at"] = i + 1
                            endpoint_results[
                                "rate_limit_status_code"
                            ] = response.status_code

                            # Capture rate limiting headers
                            rate_limit_headers = [
                                "X-RateLimit-Limit",
                                "X-RateLimit-Remaining",
                                "X-RateLimit-Reset",
                                "Retry-After",
                            ]

                            for header in rate_limit_headers:
                                if header in response.headers:
                                    endpoint_results["rate_limit_headers"][
                                        header
                                    ] = response.headers[header]

                        # Stop testing after first rate limit
                        break
                    elif response.status_code >= 500:
                        # Server error might indicate overload
                        break

                    # Small delay to avoid overwhelming the server
                    time.sleep(0.01)

                except Exception as e:
                    endpoint_results["error"] = str(e)
                    break

            # Calculate statistics
            if endpoint_results["response_times"]:
                endpoint_results["avg_response_time"] = sum(
                    endpoint_results["response_times"]
                ) / len(endpoint_results["response_times"])
                endpoint_results["max_response_time"] = max(
                    endpoint_results["response_times"]
                )

            results[endpoint] = endpoint_results

        # Overall rate limiting assessment
        endpoints_with_rate_limiting = sum(
            1
            for result in results.values()
            if result.get("rate_limiting_detected", False)
        )

        rate_limiting_score = (
            endpoints_with_rate_limiting / len(test_endpoints)
        ) * 100

        return {
            "endpoint_results": results,
            "endpoints_tested": len(test_endpoints),
            "endpoints_with_rate_limiting": endpoints_with_rate_limiting,
            "rate_limiting_score": round(rate_limiting_score, 1),
            "recommendations": self._generate_rate_limiting_recommendations(
                results
            ),
        }

    def _generate_rate_limiting_recommendations(
        self, results: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for rate limiting."""
        recommendations = []

        endpoints_without_limits = [
            endpoint
            for endpoint, data in results.items()
            if not data.get("rate_limiting_detected", False)
        ]

        if endpoints_without_limits:
            recommendations.append(
                "🔴 CRITICAL: Implement rate limiting on all API endpoints"
            )
            for endpoint in endpoints_without_limits:
                recommendations.append(f"🔴 Add rate limiting to {endpoint}")

        recommendations.extend(
            [
                "🔵 INFO: Consider implementing different rate limits for different user types",
                "🔵 INFO: Add proper rate limiting headers (X-RateLimit-*)",
                "🔵 INFO: Implement exponential backoff for rate-limited requests",
                "🔵 INFO: Monitor and log rate limiting events for analysis",
            ]
        )

        return recommendations

    def test_cors_configuration(self) -> Dict[str, Any]:
        """Test CORS (Cross-Origin Resource Sharing) configuration."""
        print("🌐 Testing CORS configuration...")

        # Test CORS with different origins
        test_origins = [
            "https://malicious.com",
            "http://localhost:3000",
            "https://example.com",
            "null",
        ]

        results = {}

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                response = self.session.get(
                    f"{self.base_url}/", headers=headers, timeout=10
                )

                cors_headers = {
                    "Access-Control-Allow-Origin": response.headers.get(
                        "Access-Control-Allow-Origin"
                    ),
                    "Access-Control-Allow-Credentials": response.headers.get(
                        "Access-Control-Allow-Credentials"
                    ),
                    "Access-Control-Allow-Methods": response.headers.get(
                        "Access-Control-Allow-Methods"
                    ),
                    "Access-Control-Allow-Headers": response.headers.get(
                        "Access-Control-Allow-Headers"
                    ),
                }

                # Check if origin is allowed
                allowed_origin = cors_headers.get("Access-Control-Allow-Origin")
                is_wildcard = allowed_origin == "*"
                origin_allowed = allowed_origin == origin or is_wildcard

                results[origin] = {
                    "status_code": response.status_code,
                    "cors_headers": {
                        k: v for k, v in cors_headers.items() if v is not None
                    },
                    "origin_allowed": origin_allowed,
                    "wildcard_used": is_wildcard,
                    "credentials_allowed": cors_headers.get(
                        "Access-Control-Allow-Credentials"
                    )
                    == "true",
                }

            except Exception as e:
                results[origin] = {"error": str(e)}

        # Analyze CORS security
        security_issues = []

        for origin, data in results.items():
            if data.get("wildcard_used", False) and data.get(
                "credentials_allowed", False
            ):
                security_issues.append(
                    "🔴 CRITICAL: Wildcard CORS with credentials enabled"
                )
            elif data.get("wildcard_used", False):
                security_issues.append(
                    "🟡 WARNING: Wildcard CORS allows all origins"
                )
            elif origin == "https://malicious.com" and data.get(
                "origin_allowed", False
            ):
                security_issues.append("🟡 WARNING: Malicious origin allowed")

        return {
            "origin_tests": results,
            "security_issues": security_issues,
            "cors_properly_configured": len(security_issues) == 0,
        }

    def run_comprehensive_security_headers_test(self) -> Dict[str, Any]:
        """Run all security header and configuration tests."""
        print("🛡️ Starting Comprehensive Security Headers Testing...")
        print("=" * 60)

        start_time = time.time()

        test_results = {
            "security_headers": self.test_security_headers(),
            "https_configuration": self.test_https_configuration(),
            "rate_limiting": self.test_rate_limiting(),
            "cors_configuration": self.test_cors_configuration(),
        }

        end_time = time.time()

        # Calculate overall security score
        scores = [
            test_results["security_headers"].get("security_score", 0),
            test_results["https_configuration"].get("https_security_score", 0),
            test_results["rate_limiting"].get("rate_limiting_score", 0),
            100
            if test_results["cors_configuration"].get(
                "cors_properly_configured", False
            )
            else 50,
        ]

        overall_score = sum(scores) / len(scores)

        final_report = {
            "test_results": test_results,
            "overall_security_score": round(overall_score, 1),
            "test_duration": end_time - start_time,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": self._generate_security_summary(test_results),
        }

        print("\n🛡️ Security Headers Testing Complete!")
        print(f"⏱️ Duration: {end_time - start_time:.2f} seconds")
        print(f"📊 Overall Security Score: {overall_score:.1f}/100")

        return final_report

    def _generate_security_summary(
        self, test_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate security summary and recommendations."""
        summary = {
            "critical_issues": [],
            "warnings": [],
            "recommendations": [],
            "strengths": [],
        }

        # Analyze security headers
        headers_data = test_results.get("security_headers", {})
        missing_headers = headers_data.get("missing_headers", [])

        if "Strict-Transport-Security" in missing_headers:
            summary["critical_issues"].append("Missing HSTS header")
        if "Content-Security-Policy" in missing_headers:
            summary["critical_issues"].append("Missing CSP header")

        # Analyze HTTPS
        https_data = test_results.get("https_configuration", {})
        if not https_data.get("https_available", False):
            summary["critical_issues"].append("HTTPS not available")
        elif not https_data.get("https_redirect", False):
            summary["warnings"].append("HTTP to HTTPS redirect not configured")

        # Analyze rate limiting
        rate_limit_data = test_results.get("rate_limiting", {})
        if rate_limit_data.get("endpoints_with_rate_limiting", 0) == 0:
            summary["critical_issues"].append("No rate limiting detected")

        # Analyze CORS
        cors_data = test_results.get("cors_configuration", {})
        cors_issues = cors_data.get("security_issues", [])
        for issue in cors_issues:
            if "CRITICAL" in issue:
                summary["critical_issues"].append(issue)
            elif "WARNING" in issue:
                summary["warnings"].append(issue)

        # Add general recommendations
        summary["recommendations"].extend(
            [
                "Implement comprehensive security headers",
                "Enable HTTPS with proper configuration",
                "Add rate limiting to all endpoints",
                "Configure CORS properly for production",
                "Regular security audits and monitoring",
            ]
        )

        return summary


if __name__ == "__main__":
    # Run security headers tests
    headers_tester = SecurityHeadersTester()
    results = headers_tester.run_comprehensive_security_headers_test()

    # Save results
    with open("security_headers_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(
        "\n📊 Security headers test results saved to security_headers_results.json"
    )
    print(f"🏆 Overall Security Score: {results['overall_security_score']}/100")
