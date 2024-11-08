import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Load the data
data = pd.read_csv('packet_log.csv')

# Check if 'timestamp' column exists
if 'timestamp' in data.columns:
    # Convert 'timestamp' to datetime format
    data['timestamp'] = pd.to_datetime(data['timestamp'])
    
    # Aggregate packet rates per 15 minutes
    data.set_index('timestamp', inplace=True)
    packet_rate = data.resample('15T').size()  # Resample every 15 minutes

    # Plotting
    plt.figure(figsize=(10, 6))
    plt.plot(packet_rate.index, packet_rate.values, marker='o', color='b')
    plt.xlabel('Time')
    plt.ylabel('Packet Rate')
    plt.title('Packet Rate Over Time')
    
    # Format x-axis labels
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.gcf().autofmt_xdate()  # Auto-format date labels for better readability

    plt.grid(True)
    plt.tight_layout()

    # Save the time series plot
    plt.savefig('packet_rate_over_time.png')
    plt.show()
else:
    print("The 'timestamp' column is missing in the CSV file.")
