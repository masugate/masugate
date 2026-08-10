#!/usr/bin/env python3
"""Run the reference demonstration Recovery demo."""

import sys

from run_reference_demos import main

if __name__ == "__main__":
    main(["recovery", *sys.argv[1:]])
