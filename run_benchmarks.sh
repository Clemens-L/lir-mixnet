#!/bin/bash
screen -dmS rng
screen -dmS powmod
screen -dmS sha256
screen -dmS zkp_correct_decryption
screen -dmS zkp_plaintext_equality_or_4
screen -dmS zkp_plaintext_equality_or_8
screen -dmS zkp_plaintext_equality_or_16
screen -dmS zkp_plaintext_dlog
screen -dmS elgamal_encrypt_decrypt

screen -S rng -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_rng.json --op rng --iterations 50000000\n'
screen -S powmod -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_powmod.json --op powmod --iterations 10000000\n'
screen -S sha256 -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_sha256.json --op sha256 --iterations 100000000\n'
screen -S zkp_correct_decryption -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_zkp_correct_decryption.json --op zkp_correct_decryption --iterations 2500000\n'
screen -S zkp_plaintext_equality_or_4 -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_zkp_plaintext_equality_or4.json --op zkp_plaintext_equality_or --iterations 500000\n'
screen -S zkp_plaintext_equality_or_8 -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_zkp_plaintext_equality_or8.json --op zkp_plaintext_equality_or --iterations 250000 --n_alternatives 8\n'
screen -S zkp_plaintext_equality_or_16 -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_zkp_plaintext_equality_or16.json --op zkp_plaintext_equality_or --iterations 100000 --n_alternatives 16\n'
screen -S zkp_plaintext_dlog -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_zkp_plaintext_dlog.json --op zkp_plaintext_dlog --iterations 2500000\n'
screen -S elgamal_encrypt_decrypt -p 0 -X stuff 'source venv/bin/activate && python benchmark.py --output benchmark_elgamal_encrypt_decrypt.json --op elgamal_encrypt_decrypt --iterations 2500000\n'
