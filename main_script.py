
from flask import Flask, request, jsonify
import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.decomposition import PCA
from clustering_utils import extract_data_from_sql, cluster_data

app = Flask(__name__)
model = SentenceTransformer('bert-large-uncased')

@app.route('/process_sql', methods=['POST'])
def process_sql():
    try:
        file_path = request.json.get('file_path')
        if not file_path:
            return jsonify({"error": "Please provide a valid file path"}), 400

        # Extract data from SQL file
        print("Extracting data from SQL file...")
        data = extract_data_from_sql(file_path)
        if not data:
            return jsonify({"error": "No data extracted from the SQL file. Please check the file format."}), 400

        columns = ["id", "title", "description", "severity", "cve", "sensor", "endpoint"]
        df = pd.DataFrame(data, columns=columns)
        print(f"Extracted {len(df)} rows of data.")

        # Text embedding using Sentence Transformer
        print("Generating text embeddings...")
        texts = df["title"] + " " + df["description"]
        text_embeddings = model.encode(texts, convert_to_tensor=True)

        # Dimensionality reduction with PCA
        print("Reducing dimensionality using PCA...")
        embed_df = pd.DataFrame(text_embeddings)
        pca = PCA(n_components=0.95)  # Retain 95% variance
        embed_reduced = pd.DataFrame(pca.fit_transform(embed_df))
        df = pd.concat([df, embed_reduced], axis=1)

        # Perform clustering
        print("Clustering data...")
        final_data = cluster_data(df)
        final_data.reset_index(drop=True, inplace=True)


        output = []
        for _, row in final_data.iterrows():
            output.append({
                "title": row["title"],
                "endpoint": row["endpoint"],
                "tag": f"group_{int(row['label'])}"
            })

        return jsonify(output)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True,use_reloader=False)
