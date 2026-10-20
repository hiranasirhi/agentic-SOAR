import pandas as pd
df = pd.read_csv('cicids2017/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv', nrows=5)
print(df.columns.tolist())