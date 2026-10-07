# CSC-225-Assignments
The code within this assignment returns the set of distinct IP addresses a given username has ever connected from, return a sorted list of usernames that connected from different ips, counted the time which had the most total login attempt, and generate alerts for locked accounts, the most suspicious IP, and any multi-IP users.

Place the code within your editor-of-choice, I use Visual Studio for example, name it [insertname].py and run the python file in terminal.

=============================================

The busiest_hour() logic:
  First, "busiest_hour" is defined, using no other variables than the code within the class "Login_monitor", or "self".
**$  def busiest_hour(self):
**
  
  Second, hour_counts is created as a list. This is due to the fact we will have to count more than one timestamp.

**$ hour_counts = {}
**
  
  Third, a "for loop" is created. "Record" is a temporary variable within "self.parsed_logs". "Self.parsed_logs" is a more organized central list, separating username, ip, timestamp and status for each line within "raw_logs". An "if" statement says that if there is a numbered timestamp, add it to the list for "timestamp", using "record" as a temporary variable to hold one timestamp. "Hour" is used to find the specific hour the timestamp was found as a login attempt and 'split' it from before " " and past ":". (For example: "2026-09-10 08:15:02" -> "08".) "Hour_counts[hour]" is used to count how many times an hour is repeated.

**$ for record in self.parsed_logs:
$    if record:
$    timestamp = record["timestamp"]
$    hour = timestamp.split(" ")[1].split(":")[0]
$    hour_counts[hour] = hour_counts.get(hour, 0) + 1
**
  
  Once the "for loop" is finished, another "if" statement is created. It states that if a variable is not "hour_counts", to return nothing. This is a safety guard to protect against any potential crashes if there were no login attempts to be found to process.

**$  if not hour_counts:
$    return None
**
  
  Next, "busiest" is used to find the hour which had the most number of attempts. "max(hour_counts," is used to sort through both hours, while "key=hour_counts.get" is used to fetch and compare which hour had the highest amount of login attempts. This is so the program doesn't automatically send "09" just because it is bigger than "08", since it tells the program to first check how many login attempts to compare it to.

**$  busiest = max(hour_counts, key=hour_counts.get)**

  
  Finally, this line returns back the "busiest" hour and the "hour_counts" for the busiest hour.

**$  return (busiest, hour_counts[busiest])
**
