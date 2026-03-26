def detect_queries_one_ip(df):

    alerts = []

    for host, group in df.groupby("host"):
        
        group = group.sort_values("timestamp") 

        intervals = group["timestamp"].diff().dropna()
     
        if len(intervals) < 4:
            continue

        seconds = intervals.dt.total_seconds()
 
        mean = seconds.mean()
        std = seconds.std()

        rel_std = std / mean if mean != 0 else 0

        unique_queries = group["query"].nunique()
        unique_ips = group["destination_ip"].nunique()
        total = len(group)

        if unique_ips > 3 and unique_queries > 5 and total > 5 and rel_std < 0.2:

            alerts.append({
                "host": host,
                "unique_queries": unique_queries,
                "unique_ips": unique_ips,
                "connections": total,
                "mean_interval": mean,
                "rel_std": rel_std
            })

    return alerts



