#!/bin/bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

chmod +x test_correlation_rules.sh

./test_correlation_rules.sh          # all 15 rule sets
./test_correlation_rules.sh 10       # just SSH brute force
./test_correlation_rules.sh ddos apt # just the original two
./test_correlation_rules.sh 13 18 20 # specific ordered rules
