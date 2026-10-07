raw_logs = [
"jdoe,192.168.1.5,2026-09-10 08:15:02,FAILED",
"jdoe,192.168.1.5,2026-09-10 08:15:10,FAILED",
"jdoe,192.168.1.5,2026-09-10 08:15:20,SUCCESS",
"mabir,10.0.0.8,2026-09-10 08:20:00,SUCCESS",
"guest,203.0.113.7,2026-09-10 08:22:11,FAILED",
"guest,203.0.113.7,2026-09-10 08:22:15,FAILED",
"guest,203.0.113.7,2026-09-10 08:22:19,FAILED",
"guest,203.0.113.7,2026-09-10 08:22:23,FAILED",
"rking,192.168.1.9,2026-09-10 08:30:00,SUCCESS",
"mabir,10.0.0.8,2026-09-10 08:31:45,FAILED",
"jdoe,172.16.0.3,2026-09-10 09:02:00,SUCCESS",
"rking,192.168.1.9,2026-09-10 09:10:00,FAILED",
]

# =========================================================
# PART 1: everything below this line is already working perfect for 
# "give me every DISTINCT ip this user has used," which is exactly problem #1 below.


class LoginMonitor:
    def __init__(self, raw_logs):
        self.raw_logs = raw_logs
        self.parsed_logs = [] #nothing parsed yet 

    def parse_line(self, line):
        """
        let's take some  string like 
        jdoe,192.168.1.5,2026-09-10 08:15:02,FAILED
        and let's turn it into a dictionary with named fields, so that the rest of our code is easier to write and maintain
        """
        parts = line.split(",")
        # username = parts[0].strip()
        # ip = parts[1].strip()
        # timestamp = parts[2].strip()
        # status = parts[3].strip()

        return {
            "username": parts[0].strip(),
            "ip": parts[1].strip(),
            "timestamp": parts[2].strip(),
            "status": parts[3].strip()
        }
    def parse_logs(self):
        self.parsed_logs = []
        for line in self.raw_logs:
            self.parsed_logs.append(self.parse_line(line))

    def failed_attempts_by_user(self):
        counts = {}
        for record in self.parsed_logs:
            if record["status"] == "FAILED":
                user = record["username"]
                counts[user] = counts.get(user, 0) + 1
            #user = record["status"] == "FAILED"
            #counts[user] = counts.get(user, 0) + 1
        return counts

    def most_sus_ip(self):
        ip_fail_counts = {}
        for record in self.parsed_logs:
            if record["status"] == "FAILED":
                ip = record["ip"]
                ip_fail_counts[ip] = ip_fail_counts.get(ip, 0) + 1
        if not ip_fail_counts:
            return None

        return max(ip_fail_counts, key=ip_fail_counts.get)
    
    def summary_report(self):
        lines = ["=== Login Monitor Summary ==="]
        counts = self.failed_attempts_by_user()
        for user, count in sorted(counts.items(),key=lambda pair: pair[1], reverse=True):
                                  lines.append(f"{user}: {count} failed attempts")
        sus = self.most_sus_ip()
        if sus:
              lines.append(f"Most suspicious IP: {sus}")

    def locked_accounts(self, threshold=3):
          counts = self.failed_attempts_by_user()
          return [user for user, count in counts.items() if count >= threshold]

    def unique_ips(self, username):
        ip_check = set()
        for record in self.parsed_logs:
            if record is None:
                continue

            if record["status"] == "ERROR":
                continue
            
            if record["username"] == username:
                ip = record["ip"]
                ip_check.add(ip)
        
        return ip_check
          

    #TODO: Return the SET of distinct IP addresses that `username` has
    # connected from, according to self.parsed_logs.
    #Look at EVERY record for this user not None, not an error)

    def multi_ip_users(self, min_ips=2):
        all_users = set(record("username") for record in self.parsed_logs if record)
        
        multi_ip = []
        for multi_ip in all_users:       
            if len(self.unique_ips("username")) >= min_ips:
                multi_ip.append("username")
                    
        return sorted(multi_ip)


    # TODO: Return a SORTED LIST of usernames who have connected from
    # at least `min_ips` different IP addresses.
    # Hint: you already have a method that tells you how many distinct
    # IPs one user has this is about traffic volume, not security risk).

    def busiest_hour(self):
        if not self.parsed_logs:
            return None
            
        hour_counts = {}
        for record in self.parsed_logs:
            if record is None:
                continue

        timestamp = record["timestamp"]
        hour = timestamp.split(" ")[1].split(":")[0]
        
        hour_counts[hour] = hour_counts.get(hour, 0) + 1
            
        if not hour_counts:
            return None
            
        # Find the hour string with the maximum number of attempts
        busiest = max(hour_counts, key=hour_counts.get)
        return (busiest, hour_counts[busiest])
         
    # Every timestamp looks like "2026-09-10 08:15:02". You need just the hour part, "08". 
    # Hint: record["timestamp"] is one string same pattern, different key.
    # Return a TUPLE: (hour_as_string, count).
    # If there's no data at all, return None (same "what if nothing's here?" guard we used in most_suspicious_ip()).
    # Example (once implemented):
    # monitor.busiest_hour() -> ('08', 10)


    #def generate_alerts(self):

    # TODO: Return a LIST of human-readable alert strings by combining
    # the other methods these are just strings, make them readable. Something like:
    # "ALERT: guest is locked out (3+ failed attempts)"
    # is a reasonable style, but write your own.
    # If NOTHING is alert-worthy, return an empty list the one where
    # `user = record["status"] == "FAILED"` silently produced a
    # dictionary keyed by True/False instead of by username. Say
    # in your own words why that bug mattered. (There's no way to guess
    # this from the code alone one clearly labeled print block
    # per method

# =========================================================
monitor = LoginMonitor(raw_logs)
monitor.parse_logs()
print(monitor.summary_report())

print(monitor.unique_ips("jdoe"))
print(monitor.unique_ips("guest"))

print(monitor.multi_ip_users())

# TODO: add a STOP & TEST style print block for unique_ips()
# (test at least two different usernames)
# TODO: add a STOP & TEST style print block for multi_ip_users()
# (test both the default and a different min_ips value)
# TODO: add a STOP & TEST style print block for busiest_hour()
# TODO: add a STOP & TEST style print block for generate_alerts()
