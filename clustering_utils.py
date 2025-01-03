import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from kneed import KneeLocator
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

def extract_data_from_sql(file_path):
    """Extracts data from a SQL file."""
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()
    data_lines = []
    in_copy_block = False


    for line in lines:
        if line.startswith("COPY public.vuln"):
            in_copy_block = True
            continue
        if in_copy_block and line.startswith("\\."):
            break
        if in_copy_block:
            data_lines.append(line.strip())
    data = [line.split("\t") for line in data_lines if line]
    return data


def cluster_data(df):
    """Clusters data based on embeddings and assigns labels."""
    end_value_counts = df['endpoint'].value_counts()
    unique_end = end_value_counts[end_value_counts == 1].index
    non_unique_end = end_value_counts[end_value_counts > 1].index

    unique_rows = df[df['endpoint'].isin(unique_end)].copy()
    unique_rows['label'] = range(len(unique_rows))

    non_unique_rows = df[df['endpoint'].isin(non_unique_end)].copy()
    current_label = len(unique_rows)  
    grouped_data = []
    columns_to_drop = ['id', 'title', 'description', 'severity', 'cve', 
                       'sensor', 'endpoint']

    for end_value, group in non_unique_rows.groupby('endpoint'):
        data_embeddings = df.drop(columns=columns_to_drop).values
        group_embeddings = data_embeddings[group.index]

        # Determine the optimal number of clusters using the Elbow Method
        inertia = []
        silhouette_scores = []
        k_range = range(1, min(len(group_embeddings), 20))

        for k in k_range:
            kmeans = KMeans(n_clusters=k, random_state=42)
            kmeans.fit(group_embeddings)
            inertia.append(kmeans.inertia_)
            if k > 1:
                silhouette_scores.append(silhouette_score(group_embeddings, kmeans.labels_))

        if len(k_range) < 2:
            optimal_k = 1  
        else:
            knee_locator = KneeLocator(k_range, inertia, curve="convex", direction="decreasing")
            optimal_k = knee_locator.knee or 1 

        print(f"Optimal number of clusters for endpoint={end_value}: {optimal_k}")
        kmeans_optimal = KMeans(n_clusters=optimal_k, random_state=42)
        group['label'] = kmeans_optimal.fit_predict(group_embeddings) + current_label

        current_label += optimal_k
        grouped_data.append(group)
    return pd.concat([unique_rows] + grouped_data)