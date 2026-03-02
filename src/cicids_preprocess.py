import pandas as pd
import numpy as np

# Files to load
files = [
    "data/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "data/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "data/cicids2017/Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv",
    "data/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"
]

# Load and merge
dfs = []
for f in files:
    df = pd.read_csv(f)
    df.columns = df.columns.str.strip()
    dfs.append(df)

df = pd.concat(dfs, ignore_index=True)
print("Loaded CICIDS rows:", df.shape[0])

# Replace infinity with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop rows with missing values
df.dropna(inplace=True)
print("After cleaning:", df.shape)

# Convert labels
df["Label"] = df["Label"].apply(lambda x: "BENIGN" if x == "BENIGN" else "ATTACK")

# Save cleaned dataset
df.to_csv("data/cicids2017/cicids_clean.csv", index=False)

print("Cleaned CICIDS dataset saved")
