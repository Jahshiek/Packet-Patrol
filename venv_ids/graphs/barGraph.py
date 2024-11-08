import pandas as pd
import matplotlib.pyplot as plt

# Load the data
data = pd.read_csv('packet_log.csv')

# Check if 'protocol' column exists
if 'protocol' in data.columns:
    # Count occurrences of each protocol
    protocol_counts = data['protocol'].value_counts()
    
    # Plot the bar chart
    plt.figure(figsize=(8, 6))
    plt.bar(protocol_counts.index, protocol_counts.values, color='skyblue')
    plt.xlabel('Protocols')
    plt.ylabel('Frequency')
    plt.title('Protocol Distribution')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save plot as image
    plt.savefig('protocol_distribution.png')
    plt.show()
else:
    print("The 'protocol' column is missing in the CSV file.")
