#!/usr/bin/env python3

import pandas as pd
import numpy as np
import joblib
import os
import sys
from datetime import datetime
import argparse
import warnings
warnings.filterwarnings('ignore')

class VoIPPredictor:
    def __init__(self, model_path="voip_isolation_forest_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.features = []
        self.encoders = {}
        
    def load_model(self):
        if not os.path.exists(self.model_path):
            print(f"❌ Model file '{self.model_path}' not found.")
            return False
            
        try:
            package = joblib.load(self.model_path)
            self.model = package["model"]
            self.scaler = package["scaler"]
            self.features = package["feature_names"]
            self.encoders = package["label_encoders"]
            print(f"✅ Model loaded from: {self.model_path}")
            print(f"📊 Model expects {len(self.features)} features")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {str(e)}")
            return False

    def preprocess_data(self, df):
        if df is None or df.empty:
            print("❌ Input data is empty")
            return None
            
        df_copy = df.copy()
        print(f"📥 Processing {len(df_copy)} records...")

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
                df_copy[col] = df_copy[col].apply(
                    lambda x: x if x in le.classes_ else le.classes_[0]
                )
                df_copy[f"{col}_encoded"] = le.transform(df_copy[col])

        for col in self.features:
            if col not in df_copy.columns:
                df_copy[col] = 0
                print(f"⚠️ Missing feature '{col}', using default value 0")

        X_new = df_copy[self.features].fillna(0)
        print(f"🔧 Features prepared: {X_new.shape}")
        
        return X_new

    def predict(self, data_path=None, data_df=None):
        if self.model is None:
            print("❌ Model not loaded. Please run load_model() first.")
            return None

        if data_df is not None:
            df = data_df
        elif data_path:
            if not os.path.exists(data_path):
                print(f"❌ Data file '{data_path}' not found.")
                return None
            try:
                df = pd.read_csv(data_path)
                print(f"📂 Loaded data from: {data_path}")
            except Exception as e:
                print(f"❌ Error loading data: {str(e)}")
                return None
        else:
            print("❌ Please provide either data_path or data_df")
            return None

        X_new = self.preprocess_data(df)
        if X_new is None:
            return None

        if self.scaler is None:
            print("❌ Scaler not loaded. Model might be incomplete.")
            return None
        try:
            X_scaled = self.scaler.transform(X_new)
        except Exception as e:
            print(f"❌ Error scaling features: {str(e)}")
            return None

        try:
            preds = self.model.predict(X_scaled)
            scores = self.model.decision_function(X_scaled)
            
            results = df.copy()
            results['is_anomaly'] = (preds == -1)
            results['anomaly_score'] = scores
            results['anomaly_prob'] = (scores - scores.min()) / (scores.max() - scores.min())
            
            total = len(results)
            anom_count = sum(results['is_anomaly'])
            anom_rate = (anom_count / total) * 100
            
            print(f"🎯 Results: {total} records, {anom_count} anomalies ({anom_rate:.2f}%)")
            
            return results
            
        except Exception as e:
            print(f"❌ Error making predictions: {str(e)}")
            return None

    def save_preds(self, results, output_path):
        if results is None:
            print("❌ No results to save")
            return False
            
        try:
            results.to_csv(output_path, index=False)
            print(f"💾 Results saved to: {output_path}")
            return True
        except Exception as e:
            print(f"❌ Error saving results: {str(e)}")
            return False

    def get_summary(self, results):
        if results is None:
            return None
            
        anomalies = results[results['is_anomaly'] == True]
        if len(anomalies) == 0:
            print("✅ No anomalies detected")
            return None
            
        print(f"\n🚨 ANOMALY SUMMARY:")
        print(f"   Found {len(anomalies)} anomalous records")
        print(f"   Scores: {anomalies['anomaly_score'].min():.3f} to {anomalies['anomaly_score'].max():.3f}")
        
        top_anom = anomalies.nlargest(5, 'anomaly_prob')
        print(f"\n🔝 Top 5 Most Anomalous:")
        for idx, row in top_anom.iterrows():
            print(f"   Record {idx}: Score={row['anomaly_score']:.3f}, Prob={row['anomaly_prob']:.3f}")
            
        return anomalies

def main():
    parser = argparse.ArgumentParser(description='VoIP Anomaly Detection Predictor')
    parser.add_argument('data_file', help='Path to CSV file containing VoIP data')
    parser.add_argument('-m', '--model', default='voip_isolation_forest_model.pkl', 
                       help='Path to trained model file')
    parser.add_argument('-o', '--output', help='Path to save prediction results')
    parser.add_argument('--summary', action='store_true', help='Show detailed anomaly summary')
    
    args = parser.parse_args()
    
    pred = VoIPPredictor(args.model)
    
    if not pred.load_model():
        sys.exit(1)
    
    results = pred.predict(args.data_file)
    if results is None:
        sys.exit(1)
    
    if args.output:
        pred.save_preds(results, args.output)
    
    if args.summary:
        pred.get_summary(results)
    
    if not args.output:
        print("\n📋 Sample Results (first 10 records):")
        print(results[['is_anomaly', 'anomaly_score', 'anomaly_prob']].head(10))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("🔮 VoIP Anomaly Predictor - Interactive Mode")
        print("=" * 50)
        
        pred = VoIPPredictor()
        
        if pred.load_model():
            test_files = ['bad.csv', 'voip_dataset_realistic_v2.csv', 'enhanced_results.csv']
            
            for test_file in test_files:
                if os.path.exists(test_file):
                    print(f"\n🧪 Testing with: {test_file}")
                    results = pred.predict(test_file)
                    if results is not None:
                        pred.get_summary(results)
                        output_file = f"predictions_{test_file}"
                        pred.save_preds(results, output_file)
                    break
            else:
                print("❌ No test data files found")
    else:
        main()
