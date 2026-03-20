def detect_beaconing(
    df,
    MIN_INTERVALS=4,
    MAX_INTERVAL_SECONDS=60,
    STD_TOLERANCE=4,
    WHITELIST=None
):
    if WHITELIST is None:
        WHITELIST = []

    alerts = []

    for (host, ip), group in df.groupby(["host", "destination_ip"]):

        # 🔹 Ignorar tráfico confiable
        if ip in WHITELIST:
            continue

        group = group.sort_values("timestamp")

        times = group["timestamp"]
        intervals = times.diff().dropna()

        if len(intervals) >= MIN_INTERVALS:
            intervals_sec = intervals.dt.total_seconds()

            if intervals_sec.std() < STD_TOLERANCE:
                if intervals_sec.mean() < MAX_INTERVAL_SECONDS:
                    alerts.append({
                        "type": "beaconing",
                        "host": host,
                        "destination_ip": ip,
                        "interval": intervals_sec.mean(),
                        "connections": len(group),
                        "severity": "high"
                    })

    return alerts
