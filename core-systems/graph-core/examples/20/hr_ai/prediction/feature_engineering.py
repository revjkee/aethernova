import pandas as pd
import numpy as np
import logging
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from hr_ai.utils.monitoring.feature_audit import log_feature_stats

logger = logging.getLogger("FeatureEngineering")
logger.setLevel(logging.INFO)

class FeatureEngineer:
    def __init__(self):
        self.pipeline = None
        self.numeric_features = []
        self.categorical_features = []

    def detect_features(self, df: pd.DataFrame) -> None:
        self.numeric_features = df.select_dtypes(include=["int64", "float64"]).columns.tolist()
        self.categorical_features = df.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
        logger.info(f"Detected {len(self.numeric_features)} numeric and {len(self.categorical_features)} categorical features")

    def build_pipeline(self) -> None:
        num_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ])
        
        cat_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse=False))
        ])

        self.pipeline = ColumnTransformer(transformers=[
            ("num", num_pipeline, self.numeric_features),
            ("cat", cat_pipeline, self.categorical_features)
        ])
        logger.info("Feature transformation pipeline constructed")

    def fit(self, df: pd.DataFrame) -> None:
        self.detect_features(df)
        self.build_pipeline()
        self.pipeline.fit(df)
        log_feature_stats(df, stage="fit")

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.pipeline:
            raise ValueError("Pipeline has not been fit. Call fit() before transform().")
        log_feature_stats(df, stage="transform")
        return self.pipeline.transform(df)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        self.fit(df)
        return self.transform(df)

    def get_feature_names(self) -> list:
        num_names = self.numeric_features
        cat_encoder = self.pipeline.named_transformers_["cat"].named_steps["encoder"]
        cat_names = cat_encoder.get_feature_names_out(self.categorical_features)
        return list(num_names) + list(cat_names)

    def export_pipeline(self, path: str) -> None:
        import joblib
        joblib.dump(self.pipeline, path)
        logger.info(f"Pipeline exported to {path}")

    def import_pipeline(self, path: str) -> None:
        import joblib
        self.pipeline = joblib.load(path)
        logger.info(f"Pipeline loaded from {path}")
