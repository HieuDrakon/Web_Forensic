import pandas as pd
import re
import sys
import csv

# Các mẫu tấn công đã chỉnh sửa
ATTACK_PATTERNS = {
    'SQL_Injection': [
        r'(?i)\b(select|union|insert|update|delete|drop|exec|from|where)\b.*?\b(table|database)\b',
        r'(?i)[\'"]\s*(or|and)\s+[\'"]?\d+[\'"]?\s*[=<>]\s*[\'"]?\d+[\'"]?',
        r'(?i)(--|\#|/\*.*?\*/)',  # SQL comment injection
        r'(?i)\b(exec|sp_executesql)\b'
    ],
    'XSS': [
        r'(?i)(<|%3C)\s*script\s*(>|%3E)',
        r'(?i)javascript\s*:',
        r'(?i)on\w+\s*=\s*["\'].*?["\']',
        r'(?i)alert\s*\(',
        r'(?i)document\.(cookie|write)',
    ],
    'Directory_Traversal': [
        r'(\.\./|\.\.%2F|\.\.%5C)',
        r'(?i)(etc/passwd|etc/shadow|etc/hosts)',
        r'(?i)(boot\.ini|windows/win\.ini)',
        r'(?i)/proc/self/environ'
    ],
    'Command_Injection': [
        r'(\||;|&|\$\(.*?\)|`.*?`)',  # Dấu hiệu command injection
        r'\b(wget|curl|nc|netcat|bash|sh\s|cmd|powershell)\b',  # các công cụ nguy hiểm
    ],
    'CSRF': [
        r'(?i)(method\s*=\s*["\']?(post|put|delete)["\']?).*?(token=)',  # Kiểm tra method + token
        r'(?i)referer\s*:\s*(http[s]?://[^/]+)'
    ],
    'Session_Hijacking': [
        r'(?i)\bsessionid=[\w-]{8,40}',
        r'(?i)cookie\s*:\s*.*?(session|token)=[^;]+',
        r'(?i)PHPSESSID=[\w-]{8,40}'
    ],
    'File_Inclusion': [
        r'(?i)\b(include|require)(_once)?\s*\(\s*["\'].*?(http[s]?|\.{2}/|/)',
        r'(?i)file=.*?(php://|http[s]?://|\.\./)'
    ],
    'Brute_Force': [
        r'(?i)POST\s+/.*?(login|signin|admin).*?HTTP/.*?"\s+40[13]',  # POST login thất bại
        r'(?i)\b(username|user)=.*?\b(password|pass)=',
    ],
    'Phishing': [
        r'(?i)\b(login|signin|account)\b.*?(http[s]?://[^/]+\.[^/]+/[^?\s]*?\.(html|php))',  # form giả mạo
        r'(?i)\bredir(ect)?=.*?(http[s]?://[^/]+\.[^/]+)'
    ],
    'Remote_Code_Execution': [
        r'(?i)\b(system|passthru|shell_exec|exec|proc_open|popen)\s*\(',
        r'(?i)\b(base64_decode|str_rot13|gzuncompress)\s*\(',
        r'(?i)\beval\s*\(\s*\$_(GET|POST|REQUEST)\['
    ],
    'XXE': [
        r'(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["\'].*?["\']>',
        r'(?i)<!DOCTYPE\s+\w+\s*\[.*?\]>'
    ]
}

def load_log_file(log_file):
    """Đọc file nhật ký Apache"""
    pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]+)"'
    )
    records = []
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                match = pattern.match(line)
                if match:
                    records.append(match.groupdict())
    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)

    return pd.DataFrame(records)

def detect_attacks(log_data):
    """Phát hiện tấn công"""
    results = []
    for index, row in log_data.iterrows():
        combined_data = ' '.join([str(row['request']), str(row['referer']), str(row['user_agent'])])
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_data):
                    results.append({
                        'timestamp': row['datetime'],
                        'ip': row['ip'],
                        'attack_type': attack_type,
                        'request': row['request'],
                        'referer': row['referer'],
                        'user_agent': row['user_agent']
                    })
                    break
    return results

def save_results(results, output_file):
    """Lưu kết quả ra file"""
    if not results:
        print("No attacks detected.")
        return

    print("\n=== Detected Attacks ===")
    print(f"{'Timestamp':<25} {'IP':<16} {'Attack Type':<20} {'Request'}")
    print("-" * 90)
    for result in results:
        print(f"{result['timestamp']:<25} {result['ip']:<16} {result['attack_type']:<20} {result['request']}")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Timestamp,IP,Attack Type,Request,Referer,User-Agent\n")
        for result in results:
            f.write(f"{result['timestamp']},{result['ip']},{result['attack_type']},"
                    f"{result['request']},{result['referer']},{result['user_agent']}\n")
    print(f"\nResults saved to {output_file}")

def main():
    log_file = "access.log"
    output_file = "detected_attacks.csv"

    print(f"Analyzing log file: {log_file}")
    log_data = load_log_file(log_file)

    print("Detecting attacks...")
    attack_results = detect_attacks(log_data)

    save_results(attack_results, output_file)

if __name__ == "__main__":
    main()
