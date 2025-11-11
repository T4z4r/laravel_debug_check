# Laravel Debug & Error-Page Leak Tester

A Python script to detect Laravel applications with debug mode enabled and potential information leaks in error pages.

## Features

- Detect `APP_DEBUG=true` (full stack trace pages)
- Detect Laravel version in debug or error pages
- Check common error codes (404, 403, 500, 422, 419)
- Optional word-list of paths to increase coverage
- Colored console output
- CSV report generation

## Usage

```bash
python3 laravel_debug_check.py https://example.com [--paths paths.txt] [--report report.csv]
```

### Arguments

- `target`: Base URL (e.g., https://example.com)
- `-p, --paths`: File with additional paths (one per line)
- `-r, --report`: CSV report output file
- `--threads`: Number of concurrent threads (default: 20)

## Installation

1. Clone or download the script.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the script as shown in the usage section.

## Requirements

- Python 3.x
- requests library

## Author

Your Name

## Date

2025-11-11