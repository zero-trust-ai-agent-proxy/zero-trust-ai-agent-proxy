from __future__ import annotations

import argparse
import json

from zero_trust_ai_agent_proxy.stats import wilson


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("k", type=int)
    parser.add_argument("n", type=int)
    args = parser.parse_args()
    print(json.dumps(wilson(args.k, args.n).as_dict(), sort_keys=True))


if __name__ == "__main__":
    main()
