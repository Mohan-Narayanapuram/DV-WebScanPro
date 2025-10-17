# Developer Notes

This document provides technical notes for contributors and developers.

## Project Structure
- `Milestone1/Week1`: Setup instructions and environment notes.
- `Milestone1/Week2`: Web crawler implementation.
- `Milestone2/Week3`: SQL Injection tester.
- `Milestone2/Week4`: XSS tester.
- `Milestone3/Week5`: Miscellaneous checks.
- `Milestone3/Week6`: IDOR tester.
- `Milestone4/Week7`: Report generator.
- `Milestone4/Week8`: Flask frontend.

## Coding Guidelines
- Follow PEP 8 for Python code style.
- Use docstrings for functions and modules.
- Results should be stored in both JSON and human-readable formats.
- Handle exceptions gracefully (avoid crashing scans).

## Development Workflow
1. Create a feature branch for new changes.
2. Test locally using DVWA or similar vulnerable apps.
3. Ensure that all modules can still integrate through `main.py`.
4. Generate a report and confirm findings display correctly.
5. Submit a pull request for review.

## Future Enhancements
- Add support for authenticated scans (session cookies, login).
- Expand payload libraries for SQLi and XSS.
- Add support for CSRF testing.
- Integrate CI/CD with GitHub Actions for automated testing and Docker builds.
