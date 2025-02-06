#!/bin/bash

echo "------------------------------------";
echo "Printing sizes for RDKGitH instances:";
echo "------------------------------------";
cargo test --release -- --exact --nocapture rdkgith::tests::test_ve_print_sizes;

