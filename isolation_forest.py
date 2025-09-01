import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score, calinski_harabasz_score, davies_bouldin_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class VoIPAnomalyDetector:
    def __init__(self, csv_path=None):
        self.csv_path = csv_path
        self.df = None
        self.X_train = None
        self.X_test = None
        self.scaler = StandardScaler()
        self.encoders = {}
        self.features = []
        self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=200, max_samples=256)
        self.X_train_scaled = None
        self.X_test_scaled = None

    def load_data(self):
        if not self.csv_path:
            print("No CSV path provided.")
            return False
        try:
            self.df = pd.read_csv(self.csv_path)
            print(f"Data loaded successfully. Shape: {self.df.shape}")
            return True
        except FileNotFoundError:
            print(f"Error: File {self.csv_path} not found.")
            return False
        except Exception as e:
            print(f"Error loading data: {str(e)}")
            return False

    def engineer_features(self):
        if self.df is None:
            print("Please load data first using load_data()")
            return None

        df_proc = self.df.copy()

        ignore_cols = [
            'call_id', 'call_duration', 'caller_ip', 'callee_ip', 
            'start_time', 'end_time', 'is_anomaly'
        ]

        if 'start_time' in df_proc.columns:
            df_proc['start_time'] = pd.to_datetime(df_proc['start_time'])
            df_proc['hour'] = df_proc['start_time'].dt.hour
            df_proc['day_of_week'] = df_proc['start_time'].dt.dayofweek

        if 'end_time' in df_proc.columns:
            df_proc['end_time'] = pd.to_datetime(df_proc['end_time'])

        if 'avg_jitter' in df_proc.columns and 'packet_loss_percent' in df_proc.columns:
            df_proc['quality_score'] = 100 - (df_proc['avg_jitter'] * 10 + df_proc['packet_loss_percent'] * 20)

        if 'bytes_per_second' in df_proc.columns:
            df_proc['bandwidth_efficiency'] = df_proc['bytes_per_second']

        if 'packets_per_second' in df_proc.columns and 'bytes_per_second' in df_proc.columns:
            df_proc['avg_packet_size'] = df_proc['bytes_per_second'] / (df_proc['packets_per_second'] + 0.001)

        num_cols = df_proc.select_dtypes(include=[np.number]).columns.tolist()

        add_id_cols = [col for col in num_cols if 'id' in col.lower()]
        exclude_cols = ignore_cols + add_id_cols
        
        exclude_cols = list(set(exclude_cols))
        feat_cols = [col for col in num_cols if col not in exclude_cols]

        cat_cols = ['codec_type', 'call_termination_method']
        for col in cat_cols:
            if col in df_proc.columns and col not in exclude_cols:
                le = LabelEncoder()
                df_proc[f'{col}_encoded'] = le.fit_transform(df_proc[col].fillna('unknown'))
                feat_cols.append(f'{col}_encoded')
                self.encoders[col] = le

        self.features = feat_cols
        X = df_proc[feat_cols].fillna(0)

        print(f"Columns ignored: {exclude_cols}")
        print(f"Features selected: {len(feat_cols)}")
        print(f"Feature names: {feat_cols}")
        return X

    def preprocess_data(self):
        X = self.engineer_features()
        if X is None:
            return False

        self.X_train, self.X_test = train_test_split(X, test_size=0.3, random_state=42)
        self.X_train_scaled = self.scaler.fit_transform(self.X_train)
        self.X_test_scaled = self.scaler.transform(self.X_test)

        print(f"Training set: {self.X_train_scaled.shape[0]} samples")
        print(f"Test set: {self.X_test_scaled.shape[0]} samples")
        return True

    def train_model(self):
        if self.X_train_scaled is None:
            print("Please run preprocess_data() first.")
            return False

        print("Training Isolation Forest...")
        self.model.fit(self.X_train_scaled)
        print("Model training complete.")

        train_pred = self.model.predict(self.X_train_scaled)
        train_anom = np.sum(train_pred == -1)
        print(f"Training anomalies: {train_anom}/{len(train_pred)}")
        return True

    def evaluate_model(self):
        if self.X_test_scaled is None:
            print("Please run preprocess_data() first.")
            return
        test_pred = self.model.predict(self.X_test_scaled)
        test_anom = np.sum(test_pred == -1)
        print(f"Test anomalies: {test_anom}/{len(test_pred)}")

        unique_labels = np.unique(test_pred)
        if len(unique_labels) < 2:
            print("⚠️ Only one cluster found. Metrics skipped.")
            return

        sil_score = silhouette_score(self.X_test_scaled, test_pred)
        ch_score = calinski_harabasz_score(self.X_test_scaled, test_pred)
        db_score = davies_bouldin_score(self.X_test_scaled, test_pred)

        print(f"Silhouette Score: {sil_score:.3f}")
        print(f"Calinski-Harabasz Score: {ch_score:.3f}")
        print(f"Davies-Bouldin Score: {db_score:.3f}")

    def detect_anomalies(self):
        if self.X_test is None or self.X_test_scaled is None:
            print("Please run preprocess_data() and train_model() first.")
            return None

        anom_scores = self.model.decision_function(self.X_test_scaled)
        test_pred = self.model.predict(self.X_test_scaled)

        results_df = self.X_test.copy()
        results_df['anomaly_score'] = anom_scores
        results_df['is_predicted_anomaly'] = (test_pred == -1)
        return results_df

    def save_model(self, path="voip_isolation_forest_model.pkl"):
        pkg = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.features,
            "label_encoders": self.encoders
        }
        joblib.dump(pkg, path)
        print(f"Model saved at: {path}")

    def load_model(self, path="voip_isolation_forest_model.pkl"):
        if not os.path.exists(path):
            print(f"Model file '{path}' not found.")
            return False
        pkg = joblib.load(path)
        self.model = pkg["model"]
        self.scaler = pkg["scaler"]
        self.features = pkg["feature_names"]
        self.encoders = pkg["label_encoders"]
        print(f"Model loaded from: {path}")
        return True

    def predict_new_data(self, new_df: pd.DataFrame):
        if self.model is None or self.scaler is None:
            print("Please train or load the model first.")
            return None

        df_copy = new_df.copy()

        ignore_cols = [
            'call_id', 'call_duration', 'caller_ip', 'callee_ip', 
            'start_time', 'end_time', 'is_anomaly'
        ]

        if 'start_time' in df_copy.columns:
            df_copy['start_time'] = pd.to_datetime(df_copy['start_time'])
            df_copy['hour'] = df_copy['start_time'].dt.hour
            df_copy['day_of_week'] = df_copy['start_time'].dt.dayofweek

        if 'end_time' in df_copy.columns:
            df_copy['end_time'] = pd.to_datetime(df_copy['end_time'])

        if 'avg_jitter' in df_copy.columns and 'packet_loss_percent' in df_copy.columns:
            df_copy['quality_score'] = 100 - (df_copy['avg_jitter'] * 10 + df_copy['packet_loss_percent'] * 20)

        if 'bytes_per_second' in df_copy.columns:
            df_copy['bandwidth_efficiency'] = df_copy['bytes_per_second']

        if 'packets_per_second' in df_copy.columns and 'bytes_per_second' in df_copy.columns:
            df_copy['avg_packet_size'] = df_copy['bytes_per_second'] / (df_copy['packets_per_second'] + 0.001)

        for col, le in self.encoders.items():
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].fillna('unknown')
                df_copy[col] = df_copy[col].apply(lambda x: x if x in le.classes_ else 'unknown')
                df_copy[f"{col}_encoded"] = le.transform(df_copy[col])

        for col in self.features:
            if col not in df_copy.columns:
                df_copy[col] = 0

        X_new = df_copy[self.features].fillna(0)
        X_scaled = self.scaler.transform(X_new)

        preds = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        results = new_df.copy()
        results['is_anomaly'] = (preds == -1)
        results['anomaly_score'] = scores
        return results

    def run_analysis(self):
        print("VOIP ANOMALY DETECTION SYSTEM")
        print("="*60)
        if not self.load_data():
            return False
        if not self.preprocess_data():
            return False
        if not self.train_model():
            return False
        self.evaluate_model()
        results = self.detect_anomalies()
        print("="*60)
        print("ANALYSIS COMPLETE ✓")
        print("="*60)
        return results


if __name__ == "__main__":
    print("Starting VoIP Anomaly Detection Model Training...")
    detector = VoIPAnomalyDetector("/home/meerpi/hackathon/SIPP/voip_dataset_realistic_v2.csv")
    results = detector.run_analysis()
    
    detector.save_model("voip_isolation_forest_model.pkl")
    print("Model training completed and saved successfully!")
