import yaml

def load_feed_config(feed_name, config_file="config/feed_registry.yaml"):
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    return config.get(feed_name, {})
