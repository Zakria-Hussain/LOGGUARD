# Generates data/auth.log with synthetic SSH authentication logs and planted attack scenarios:
#   1. benign: regular logins from office IPs with occasional typos
#   2. burst: brute force burst of ~300 failed attempts within 10 minutes
#   3. slow: slow brute force across 12 different IPs over the night
#   4. stuffing: credential stuffing across 25 IPs with various usernames
#   5. breakin: attacker fails 40 times and then succeeds at 04:02:11
# Also generates realistic background noise (CRON jobs, closed connections).
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
START = datetime(2026, 10, 28, 0, 0, 0)

lines = []   # list of (datetime, text)

OFFICE_IPS = ['192.0.2.10', '192.0.2.11', '192.0.2.12', '192.0.2.13']
USERS = ['alice', 'bob', 'deploy']
BURST_IP = '203.0.113.50'
ATTACKER_IP = '198.51.100.77'
STUFF_USERS = ['admin', 'oracle', 'ubuntu', 'postgres', 'mysql', 'test',
               'guest', 'user', 'git', 'pi', 'admin1']


def pid():
    return random.randint(1000, 9999)


def fail(ts, ip, user, invalid=True):
    who = f'invalid user {user}' if invalid else user
    lines.append((ts, f'{ts:%b %d %H:%M:%S} server1 sshd[{pid()}]: Failed password '
                      f'for {who} from {ip} port {random.randint(30000, 65000)} ssh2'))


def accept(ts, ip, user):
    lines.append((ts, f'{ts:%b %d %H:%M:%S} server1 sshd[{pid()}]: Accepted password '
                      f'for {user} from {ip} port {random.randint(30000, 65000)} ssh2'))


def noise(ts, ip=None):
    ip = ip or random.choice(OFFICE_IPS + ['198.51.100.200'])
    kind = random.random()
    if kind < 0.5:
        lines.append((ts, f'{ts:%b %d %H:%M:%S} server1 sshd[{pid()}]: Connection closed '
                          f'by {ip} port {random.randint(30000, 65000)} [preauth]'))
    elif kind < 0.8:
        lines.append((ts, f'{ts:%b %d %H:%M:%S} server1 sshd[{pid()}]: Received disconnect '
                          f'from {ip} port {random.randint(30000, 65000)}:11: Bye Bye [preauth]'))
    else:
        lines.append((ts, f'{ts:%b %d %H:%M:%S} server1 CRON[{pid()}]: pam_unix(cron:session): '
                          f'session opened for user root by (uid=0)'))


def scenario_benign():
    """Daytime logins from the office, plus 3 single typos (1 fail then a success)."""
    for user in USERS:
        ip = random.choice(OFFICE_IPS)
        t = START + timedelta(hours=random.randint(6, 9), minutes=random.randint(0, 59))
        while t < START + timedelta(hours=22):
            accept(t, ip, user)
            t += timedelta(minutes=random.randint(20, 55))
    # typos: a failed attempt, then the same user gets it right ~30s later
    typo_ips = []
    for user, ip in [('alice', OFFICE_IPS[0]), ('bob', OFFICE_IPS[1]), ('deploy', OFFICE_IPS[2])]:
        t = START + timedelta(hours=random.randint(9, 17), minutes=random.randint(0, 59))
        fail(t, ip, user, invalid=False)
        accept(t + timedelta(seconds=random.randint(15, 45)), ip, user)
        typo_ips.append(ip)
    return typo_ips


def scenario_burst():
    """ONE IP, 300 failed logins inside the 10 minutes from 01:30 to 01:40."""
    n = 300
    for _ in range(n):
        t = START + timedelta(hours=1, minutes=30, seconds=random.randint(0, 599))
        user = random.choice(['root', 'admin', 'test'])
        fail(t, BURST_IP, user, invalid=(user != 'root'))
    return n


def scenario_slow():
    """12 IPs, each only 3-5 failures spread over 00:00-06:00, against root/admin."""
    ips = [f'198.51.100.{i}' for i in range(10, 22)]   # .77 is the attacker, leave it alone
    for ip in ips:
        for _ in range(random.randint(3, 5)):
            t = START + timedelta(seconds=random.randint(0, 6 * 3600 - 1))
            user = random.choice(['root', 'admin'])
            fail(t, ip, user, invalid=(user == 'admin'))
    return ips


def scenario_stuffing():
    """25 IPs, each 1-2 failures, each a different username - no IP stands out alone."""
    ips = [f'192.0.2.{i}' for i in range(100, 125)]
    names = [random.choice(STUFF_USERS) for _ in range(40)]
    k = 0
    for ip in ips:
        for _ in range(random.randint(1, 2)):
            t = START + timedelta(hours=random.randint(2, 5), minutes=random.randint(0, 59))
            fail(t, ip, names[k % len(names)])
            k += 1
    return ips


def scenario_breakin():
    """40 failures from the attacker between 02:00 and 03:50, then one success at 04:02:11."""
    for _ in range(40):
        t = START + timedelta(hours=2, minutes=random.randint(0, 110), seconds=random.randint(0, 59))
        user = random.choice(['root', 'admin'])
        fail(t, ATTACKER_IP, user, invalid=(user == 'admin'))
    success_ts = START + timedelta(hours=4, minutes=2, seconds=11)
    accept(success_ts, ATTACKER_IP, 'deploy')
    return success_ts


def main():
    typo_ips = scenario_benign()
    burst_n = scenario_burst()
    slow_ips = scenario_slow()
    stuff_ips = scenario_stuffing()
    success_ts = scenario_breakin()

    # a real log is mostly noise: pad the whole day so the file has a few thousand lines
    for _ in range(2400):
        t = START + timedelta(seconds=random.randint(0, 24 * 3600 - 1))
        noise(t)

    lines.sort(key=lambda x: x[0])

    out = Path(__file__).parent
    (out / 'auth.log').write_text('\n'.join(text for _, text in lines) + '\n', encoding='utf-8')

    truth = {
        'benign': {'users': USERS, 'ips': OFFICE_IPS, 'typo_ips': typo_ips},
        'burst': {'ips': [BURST_IP], 'failed': burst_n, 'window': '01:30-01:40'},
        'slow': {'ips': slow_ips},
        'stuffing': {'ips': stuff_ips},
        'breakin': {'ips': [ATTACKER_IP], 'user': 'deploy',
                    'success_time': f'{success_ts:%b %d %H:%M:%S}'},
    }
    (out / 'truth.json').write_text(json.dumps(truth, indent=2), encoding='utf-8')
    print(f'wrote {len(lines)} lines to data/auth.log and data/truth.json')


if __name__ == '__main__':
    main()
