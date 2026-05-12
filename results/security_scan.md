# DevSecOps scan report

Run on 2026-05-13 against the release tree at HEAD of `main`.

## Bandit (medium severity and above)

```
$ bandit -r audit cli.py config.py -ll
Run metrics:
    Total issues (by severity):
        Undefined: 0
        Low: 0
        Medium: 0
        High: 0
    Total lines of code: 840
```

## pip-audit

```
$ pip-audit --skip-editable
No known vulnerabilities found
```

## Semgrep (p/python + p/security-audit)

```
$ semgrep --config p/python --config p/security-audit --error --quiet \
      audit cli.py config.py
exit=0
```
