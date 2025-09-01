#!/usr/bin/env python3

"""
VoIP Anomaly Detection Predictor

This module provides anomaly detection for VoIP call data using machine learning.
It automatically handles missing data by using intelligent defaults calculated from
reference datasets.

IMPORTANT: The following columns are ALWAYS IGNORED during training and testing:
- call_id: Unique identifier (not a feature)
- call_duration: Metadata (not a feature) 
- caller_ip: IP address (not a feature)
- callee_ip: IP address (not a feature)
- start_time: Timestamp (used only for derived features like hour/day)
- end_time: Timestamp (metadata)
- is_anomaly: Target variable (not a feature)

These columns are preserved in the output for reference but never used as ML features.
"""

import pandas as pd
import numpy as np
import joblib
import os
import sys
from datetime import datetime
import argparse
import warnings
from voip_constants import get_ignored_columns, get_categorical_columns, FIXED_DEFAULTS
warnings.filterwarnings('ignore')

class VoIPPredictor:
    def __init__(self, model_path="voip_isolation_forest_model.pkl", reference_data_path="/home/meerpi/hackathon/SIPP/voip_dataset_realistic_v2.csv"):
        self.model_path = model_path
        self.reference_data_path = reference_data_path
        self.model = None
        self.scaler = None
        self.features = []
        self.encoders = {}
        self.reference_defaults = {}
        
    def get_ignored_columns(self):
        """Return list of columns that should always be ignored during feature processing"""
        return get_ignored_columns()
        
    def load_reference_defaults(self):
        """Load and calculate intelligent defaults from reference dataset"""
        if not os.path.exists(self.reference_data_path):
            print(f"⚠️ Reference data file '{self.reference_data_path}' not found. Using fixed defaults.")
            return self._get_fixed_defaults()
        
        try:
            ref_df = pd.read_csv(self.reference_data_path)
            print(f"📚 Loading reference defaults from: {self.reference_data_path}")
            print(f"📊 Reference dataset: {len(ref_df)} records")
            
            # Calculate numeric defaults from averages (excluding ignored columns)
            ignore_cols = self.get_ignored_columns()
            
            numeric_defaults = {}
            numeric_cols = ref_df.select_dtypes(include=[np.number]).columns
            for col in numeric_cols:
                if col not in ignore_cols:  # Skip ignored columns
                    avg_val = ref_df[col].mean()
                    numeric_defaults[col] = avg_val
            
            # Calculate categorical defaults from mode
            categorical_defaults = {}
            categorical_cols = get_categorical_columns()
            for col in categorical_cols:
                if col in ref_df.columns:
                    mode_val = ref_df[col].mode().iloc[0] if not ref_df[col].mode().empty else 'unknown'
                    categorical_defaults[col] = mode_val
            
            defaults = {**numeric_defaults, **categorical_defaults}
            print(f"✅ Loaded {len(defaults)} intelligent defaults from reference data")
            return defaults
            
        except Exception as e:
            print(f"⚠️ Error loading reference data: {e}. Using fixed defaults.")
            return self._get_fixed_defaults()
    
    def _get_fixed_defaults(self):
        """Fallback to fixed defaults if reference data is unavailable"""
        return FIXED_DEFAULTS.copy()
        
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
            
            # Load intelligent defaults from reference data
            self.reference_defaults = self.load_reference_defaults()
            
            return True
        except Exception as e:
            print(f"❌ Error loading model: {str(e)}")
            return False

        
    def validate_data(self, df):
        """Validate input data quality and provide recommendations"""
        if df is None or df.empty:
            return False
            
        print(f"\n🔍 DATA QUALITY REPORT:")
        print(f"   📊 Total records: {len(df)}")
        
        # Check for completely empty rows
        empty_rows = df.isnull().all(axis=1).sum()
        if empty_rows > 0:
            print(f"   ⚠️  Completely empty rows: {empty_rows}")
        
        # Check missing data percentage
        missing_pct = (df.isnull().sum().sum() / (len(df) * len(df.columns))) * 100
        print(f"   📈 Overall missing data: {missing_pct:.1f}%")
        
        # Check for critical fields (excluding ignored columns)
        ignore_cols = self.get_ignored_columns()
        critical_fields = ['avg_jitter', 'packet_loss_percent', 'codec_type']
        for field in critical_fields:
            if field in df.columns and field not in ignore_cols:
                missing = df[field].isnull().sum()
                if missing > 0:
                    pct = (missing / len(df)) * 100
                    print(f"   🔴 Critical field '{field}': {missing} missing ({pct:.1f}%)")
        
        # Data quality recommendations
        if missing_pct > 50:
            print("   💡 Recommendation: High missing data detected. Consider data collection improvements.")
        elif missing_pct > 20:
            print("   💡 Recommendation: Moderate missing data. Results may be less reliable.")
        else:
            print("   ✅ Good data quality for prediction.")
            
        return True

    def preprocess_data(self, df):
        if df is None or df.empty:
            print("❌ Input data is empty")
            return None
            
        df_copy = df.copy()
        
        # Handle empty strings and convert them to NaN for proper handling
        df_copy = df_copy.replace('', np.nan)
        df_copy = df_copy.replace(' ', np.nan)  # Also handle spaces

        # Columns to always ignore during feature processing
        ignore_cols = self.get_ignored_columns()

        # Handle datetime fields with better error handling
        if 'start_time' in df_copy.columns:
            df_copy['start_time'] = pd.to_datetime(df_copy['start_time'], errors='coerce')
            df_copy['hour'] = df_copy['start_time'].dt.hour
            df_copy['day_of_week'] = df_copy['start_time'].dt.dayofweek
            # Fill missing datetime-derived features
            df_copy['hour'] = df_copy['hour'].fillna(12)  # Default to noon
            df_copy['day_of_week'] = df_copy['day_of_week'].fillna(0)  # Default to Monday

        if 'end_time' in df_copy.columns:
            df_copy['end_time'] = pd.to_datetime(df_copy['end_time'], errors='coerce')

        # Handle numeric fields with intelligent defaults from reference data
        numeric_defaults = {k: v for k, v in self.reference_defaults.items() 
                          if isinstance(v, (int, float))}
        
        for col, default_val in numeric_defaults.items():
            if col in df_copy.columns:
                df_copy[col] = pd.to_numeric(df_copy[col], errors='coerce').fillna(default_val)

        # Create derived features with safe division using intelligent defaults
        if 'avg_jitter' in df_copy.columns and 'packet_loss_percent' in df_copy.columns:
            jitter_safe = df_copy['avg_jitter'].fillna(numeric_defaults.get('avg_jitter', 0.01))
            loss_safe = df_copy['packet_loss_percent'].fillna(numeric_defaults.get('packet_loss_percent', 0.0))
            df_copy['quality_score'] = 100 - (jitter_safe * 10 + loss_safe * 20)

        if 'bytes_per_second' in df_copy.columns:
            df_copy['bandwidth_efficiency'] = df_copy['bytes_per_second'].fillna(
                numeric_defaults.get('bytes_per_second', 8000))

        if 'packets_per_second' in df_copy.columns and 'bytes_per_second' in df_copy.columns:
            pps_safe = df_copy['packets_per_second'].fillna(numeric_defaults.get('packets_per_second', 50.0))
            bps_safe = df_copy['bytes_per_second'].fillna(numeric_defaults.get('bytes_per_second', 8000.0))
            df_copy['avg_packet_size'] = bps_safe / (pps_safe + 0.001)

        # Handle categorical fields with intelligent defaults
        categorical_defaults = {k: v for k, v in self.reference_defaults.items() 
                              if isinstance(v, str)}
        
        for col, le in self.encoders.items():
            if col in df_copy.columns:
                # Fill missing categorical values with intelligent defaults
                default_val = categorical_defaults.get(col, 'unknown')
                df_copy[col] = df_copy[col].fillna(default_val)
                
                # Handle values not seen during training
                df_copy[col] = df_copy[col].apply(
                    lambda x: x if x in le.classes_ else le.classes_[0]
                )
                df_copy[f"{col}_encoded"] = le.transform(df_copy[col])

        # Ensure all required features exist with intelligent defaults
        for col in self.features:
            if col not in df_copy.columns:
                if col.endswith('_encoded'):
                    df_copy[col] = 0  # Encoded categorical default
                elif col in numeric_defaults:
                    df_copy[col] = numeric_defaults[col]
                else:
                    df_copy[col] = 0

        # Final data preparation with comprehensive cleaning
        X_new = df_copy[self.features]
        
        # Handle any remaining NaN values
        X_new = X_new.fillna(0)
        
        # Check for infinite values
        inf_mask = np.isinf(X_new.values)
        if inf_mask.any():
            X_new = X_new.replace([np.inf, -np.inf], 0)
        
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

        # Validate data quality first
        self.validate_data(df)
        
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
            print(f"   Expected features: {len(self.features)}")
            print(f"   Provided features: {X_new.shape[1]}")
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
    parser.add_argument('-r', '--reference', default='/home/meerpi/hackathon/SIPP/voip_dataset_realistic_v2.csv',
                       help='Path to reference dataset for intelligent defaults')
    parser.add_argument('-o', '--output', help='Path to save prediction results')
    parser.add_argument('--summary', action='store_true', help='Show detailed anomaly summary')
    
    args = parser.parse_args()
    
    pred = VoIPPredictor(args.model, args.reference)
    
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
        print("\n Sample Results (first 10 records):")
        print(results[['is_anomaly', 'anomaly_score', 'anomaly_prob']].head(10))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(" VoIP Anomaly Predictor - Interactive Mode")
        print("=" * 50)
        
        pred = VoIPPredictor()
        
        if pred.load_model():
            test_files = ['bad_predictions.csv', 'voip_dataset_realistic_v2.csv', 'enhanced_results.csv']
            
            for test_file in test_files:
                if os.path.exists(test_file):
                    print(f"\n Testing with: {test_file}")
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
