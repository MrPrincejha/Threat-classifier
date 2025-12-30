import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
import pickle

# Load dataset
df = pd.read_csv(os.path.join("ml", "lstm_threat_dataset.csv"))


# Drop timestamp
df = df.drop(columns=['Timestamp'])

# Encode Protocol
protocol_encoder = LabelEncoder()
df['Protocol'] = protocol_encoder.fit_transform(df['Protocol'])

# Encode Label
label_encoder = LabelEncoder()
df['Label'] = label_encoder.fit_transform(df['Label'])
num_classes = len(label_encoder.classes_)

# Convert IP to integer format
def ip_to_int(ip):
    parts = ip.split(".")
    return sum([int(parts[i]) << (8*(3-i)) for i in range(4)])

df['Source_IP'] = df['Source_IP'].apply(ip_to_int)
df['Destination_IP'] = df['Destination_IP'].apply(ip_to_int)

# Select features and labels
X = df[['Source_IP', 'Destination_IP', 'Port', 'Protocol', 'Packet_Size']].values
y = df['Label'].values

# Scale numeric features
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Create LSTM Sequences
sequence_length = 10
X_seq = []
y_seq = []

for i in range(len(X_scaled) - sequence_length):
    X_seq.append(X_scaled[i:i+sequence_length])
    y_seq.append(y[i+sequence_length])

X_seq, y_seq = np.array(X_seq), np.array(y_seq)

# Build LSTM Model
model = Sequential()
model.add(LSTM(64, input_shape=(sequence_length, X_seq.shape[2]), return_sequences=False))
model.add(Dropout(0.2))
model.add(Dense(32, activation='relu'))
model.add(Dense(num_classes, activation='softmax'))

model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

print("Training model...")
model.fit(X_seq, y_seq, epochs=12, batch_size=64)

# Create ML folder if not exists
os.makedirs("ml", exist_ok=True)

# Save model and preprocessors
model.save("ml/threat_lstm.keras")

with open("ml/protocol_encoder.pkl", "wb") as f:
    pickle.dump(protocol_encoder, f)

with open("ml/label_encoder.pkl", "wb") as f:
    pickle.dump(label_encoder, f)

with open("ml/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

print("Training Completed! Model Saved.")
