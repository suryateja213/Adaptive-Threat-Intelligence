def merge_cloud_feeds():
    import pandas as pd
    import os
    from datetime import datetime

    base_dir = "data_feeds"
    feeds = ["threatfox", "phishtank", "malwarebazaar", "ransomwatch", "firehol"]
    label_map = {
        "threatfox": "malicious",
        "phishtank": "phishing",
        "malwarebazaar": "malware",
        "ransomwatch": "ransomware",
        "firehol": "ip_blocklist"
    }

    merged_frames = []

    for feed in feeds:
        # Support both flat and nested storage formats
        flat_path = os.path.join(base_dir, f"{feed}_master.csv")
        nested_path = os.path.join(base_dir, feed, f"{feed}_master.csv")

        if os.path.exists(flat_path):
            df = pd.read_csv(flat_path, low_memory=False)
            print(f"Loaded flat: {flat_path}")
        elif os.path.exists(nested_path):
            df = pd.read_csv(nested_path, low_memory=False)
            print(f"Loaded nested: {nested_path}")
        else:
            print(f"Missing: {flat_path} and {nested_path}")
            continue

        df["source"] = feed
        df["label"] = label_map.get(feed, "malicious")  # Default fallback
        df["label_binary"] = 1  # All cloud data is malicious
        df["ingestion_time"] = datetime.utcnow().isoformat()

        merged_frames.append(df)

    if not merged_frames:
        print("No datasets found to merge.")
        return

    merged_df = pd.concat(merged_frames, ignore_index=True)

    timestamp = datetime.utcnow().strftime("%Y_%m_%d")
    cloud_out_dir = os.path.join(base_dir, "processed", "cloud", timestamp)
    os.makedirs(cloud_out_dir, exist_ok=True)

    output_filename = "cloud_labeled_threats.csv"
    output_path = os.path.join(cloud_out_dir, output_filename)
    merged_df.to_csv(output_path, index=False)

    pointer_file = os.path.join(base_dir, "processed", "cloud", "latest_cloud_version.txt")
    with open(pointer_file, "w") as f:
        f.write(os.path.join(timestamp, output_filename))

    print(f"Cloud master saved to: {output_path}")
    print(f"Pointer updated at: {pointer_file}")


if __name__ == "__main__":
    merge_cloud_feeds()
