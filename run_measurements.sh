#!/bin/bash
source venv/bin/activate
FD_LIMIT=$((2**18))
echo File descriptor limit: $(ulimit -n)
echo Setting limit to $FD_LIMIT ...
ulimit -n $FD_LIMIT
echo New file descriptor limit: $(ulimit -n)
# Completed: Folder 2021-12-13T11-20-06
# python eval.py --range_consortium_peers 2 --range_mix_peers "[3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47]" --range_user_inputs "[10]" --iters 30
# Completed: Folder 2021-12-17T10-55-28
# python eval.py --range_consortium_peers 2 --range_mix_peers "[3]" --range_user_inputs "[10, 20, 30, 40, 50, 100, 150, 200, 250]" --iters 30
# Completed: Folder 2021-12-22T18-04-24
# python eval.py --range_consortium_peers 2 --range_mix_peers "[5]" --range_user_inputs "[10, 20, 30, 40, 50, 100, 150, 200, 250]" --iters 30
# Completed: Folder 2022-01-03T17-24-17
# python eval.py --range_consortium_peers 2 --range_mix_peers "[7]" --range_user_inputs "[10, 20, 30, 40, 50, 100, 150, 200, 250]" --iters 30
# Test scaling of full vs. single recovery with inputs and mix peers (small experiment for now)
# Completed: Folder 2022-01-18T23-48-43
# python eval.py --range_consortium_peers "[47]" --range_mix_peers "[3]" --range_user_inputs "[10, 100]" --recovery "[0, 1]" --precomputed-dkg --iters 30
# Test scaling of whole protocol with many consortium peers, also full vs. single
# Completed: Folder 2022-01-20T03-41-11
# python eval.py --range_consortium_peers "[3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47]" --range_mix_peers "[3]" --range_user_inputs "[10]" --recovery "[0, 1]" --precomputed-dkg --iters 30
# More iterations for DKG performance
# Completed: Folder 2022-01-21T15-32-37
# python eval.py --range_consortium_peers "[3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47]" --range_mix_peers "[3]" --range_user_inputs "[1]" --recovery "[0]" --iters 30
