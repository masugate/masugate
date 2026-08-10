#!/usr/bin/env python3
"""Run the reference demonstration Receipt demo."""

import sys

from run_reference_demos import main

if __name__ == "__main__":
    main(["receipt", *sys.argv[1:]])
