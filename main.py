"""CLI entrypoint."""
import argparse
import sys

# Import solver modules for their registration side-effects once they exist.
try:
    import solvers.injection  # noqa: F401
except ImportError:
    pass
try:
    import solvers.xss  # noqa: F401
except ImportError:
    pass
try:
    import solvers.broken_auth  # noqa: F401
except ImportError:
    pass
try:
    import solvers.sensitive_data  # noqa: F401
except ImportError:
    pass
try:
    import solvers.broken_access_control  # noqa: F401
except ImportError:
    pass
try:
    import solvers.improper_input_validation  # noqa: F401
except ImportError:
    pass
try:
    import solvers.vulnerable_components  # noqa: F401
except ImportError:
    pass
try:
    import solvers.cryptographic_issues  # noqa: F401
except ImportError:
    pass
try:
    import solvers.security_misconfiguration  # noqa: F401
except ImportError:
    pass
try:
    import solvers.observability_failures  # noqa: F401
except ImportError:
    pass
try:
    import solvers.miscellaneous  # noqa: F401
except ImportError:
    pass
try:
    import solvers.broken_anti_automation  # noqa: F401
except ImportError:
    pass
try:
    import solvers.security_through_obscurity  # noqa: F401
except ImportError:
    pass
try:
    import solvers.unvalidated_redirects  # noqa: F401
except ImportError:
    pass
try:
    import solvers.insecure_deserialization  # noqa: F401
except ImportError:
    pass
try:
    import solvers.xxe  # noqa: F401
except ImportError:
    pass

from core.runner import run_all
from report import print_report
from setup import full_setup


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP Juice Shop challenge automator")
    parser.add_argument("--setup", action="store_true", help="Clone/install/start Juice Shop first")
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--category", action="append", dest="categories", default=None,
                         help="Limit to one or more categories (repeatable)")
    args = parser.parse_args()

    if args.setup:
        full_setup(base_url=args.base_url)

    results = run_all(base_url=args.base_url, categories=args.categories)
    print_report(results)

    if any(not r["solved"] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
