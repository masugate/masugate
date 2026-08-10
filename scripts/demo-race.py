#!/usr/bin/env python3
"""Run the reference demonstration Race demo."""

import sys

from run_reference_demos import main

if __name__ == "__main__":
    main(["race", *sys.argv[1:]])
