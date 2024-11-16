# Git Repository Exposure Scanner
![Python](https://img.shields.io/badge/python-v3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A powerful and efficient security tool designed to detect exposed Git repositories across multiple domains. This tool helps security researchers and system administrators identify potentially vulnerable Git repositories that might expose sensitive information.

## 🔍 Overview

The Git Repository Exposure Scanner is a security tool that helps identify exposed .git directories on web servers. This exposure can lead to source code disclosure and potentially sensitive information leakage. The tool performs comprehensive checks against multiple domains simultaneously using multi-threading for efficiency.

## 🚀 Features

- Multi-threaded scanning for fast execution
- Comprehensive Git path checking
- Support for both HTTP and HTTPS
- Configurable scan delays and timeouts
- Detailed reporting with status codes and file sizes
- Verbose mode for debugging
- Output file support for documentation
- Custom domain list support

## 📋 Prerequisites

- Python 3.6+
- Required Python packages:
  ```
  requests
  ```

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/toniilic/Git-Vulnerabilty-Scanner.git
cd Git-Vulnerabilty-Scanner
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## 💻 Usage

Basic usage:
```bash
python3 git_scanner.py -f domains.txt
```

Advanced usage with all options:
```bash
python3 git_scanner.py -f domains.txt -o results.txt -t 5 -d 1 -v
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| -f, --file | File containing list of domains (required) | None |
| -o, --output | Output file for results | None (prints to stdout) |
| -t, --threads | Number of concurrent threads | 5 |
| -d, --delay | Delay between requests in seconds | 1 |
| -v, --verbose | Enable verbose output | False |

## 🛡️ Security Considerations

- Use this tool only on domains you have permission to test
- Respect rate limits and robots.txt files
- Consider the impact of concurrent scanning on target servers
- Handle discovered information responsibly

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

## 🐛 Bug Reporting

Found a bug? Please open an issue in our [issue tracker](https://github.com/toniilic/Git-Vulnerabilty-Scanner/issues) with:
- Clear bug description
- Steps to reproduce
- Expected vs actual behavior
- Your environment details

## 📞 Support

- Report bugs via [GitHub Issues](https://github.com/toniilic/Git-Vulnerabilty-Scanner/issues)
- For major changes, please open an issue first to discuss what you would like to change
