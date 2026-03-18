"""
Brute Force Detector

Detects multiple failed login attempts per user,
which may indicate a brute force attack.

Logic:
- Groups logs by user
- Counts failed login attempts
- Triggers alert if attempts exceed threshold
"""



def detect_bruteforce(df):

    alerts = []

    for user in df["user"].unique():

        user_logs = df[df["user"] == user]

        failed = user_logs[user_logs["status"] == "failed"]

        if len(failed) >= 5:

            alerts.append({
                "type": "brute_force",
                "user": user,
                "attempts": len(failed)
            })

    return alerts


