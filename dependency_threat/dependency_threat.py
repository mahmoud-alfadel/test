from dependency_threat.helper.step1 import fetch_dependency_history
from dependency_threat.helper.step2 import identifying_vulnerability_levels
from dependency_threat.helper.step3 import repo_commits_combiner
from dependency_threat.helper.step4 import find_commits_at_intervals

access_tokens = [
    "c1efcd24dd9ed43fdf153c57603328bef73c3c3b",
    "0659f7a9ae2a5451f99bc1536dc9776320e0e149",
    "0b420fbb5fd82feee1da9cd690d08d88eca9351b",
    "683d946e3418ec98db60fc31f080cb1194ad27ac",
    "4ae1d5e61def24fb693296955b1b7072c5c59446",
    "18397c99faf1f0e636a46a021d2be77e56aebcae",
    "7bbe429fb29f0b30998122104c99e111a1a6b209",
    "29d7055440bb9173a7e41081e8eea90d525b78ac",
    "6f1f7fd8e6b854db0ebea74c3e5825ab8444d594",
]


def analyze(github_url, interval=5):
    print("Running Step 1: fetching dependency history")
    df = fetch_dependency_history(github_url, access_tokens)
    print("Running Step 2: identifying vulnerability levels")
    df = identifying_vulnerability_levels(df)
    print("Running Step 3: combining repo commits")
    df = repo_commits_combiner(df)
    print("Running Step 4: Finding commits at intervals")
    result_df = find_commits_at_intervals(df, interval)
    print("Done.")
    return result_df
