# Limited Identity Recovery for Mixing Networks

A prototypical implementation of a protocol for mixing networks that allows a consortium of trusted parties
to recover the identities of anonymized users.

The consortium uses threshold cryptography to decrypt deanonymization secrets published by the _mix peers_
providing the mixing service.

During the mixing operation, the mix peers prove the validity of the encrypted deanonymization secrets by performing a 
number of _zero-knowledge proofs of knowledge_ (ZKPoK). An important building block
in our proof construction is _A commitment-consistent proof of a shuffle_ by D. Wikström (2009).

The protocol is applicable to _partially dishonest_ mixing networks (and consortiums):
For any $t < m / 2$, an attacker controlling $t$ peers cannot disrupt the mixing operation
nor prevent a subsequent identity recovery by the consortium.

## Requirements

Aside from the python packages in `requirements.txt` (install using `$ pip install -r requirements.txt`), the following packages must be installed beforehand (as they are required for installing `gmpy2`):

`$ sudo apt-get install -y python3.8-dev libmpfr-dev libmpc-dev libgmp-dev` (for modern Ubuntu systems)

Package names should be similar for other distributions.

## Usage

The script `mixnet_execution.sh` performs a full execution of the protocol:

1. **Consortium**: Perform _distributed key generation_ (DKG)
2. **Mixing Network**: Initialize and perform DKG
3. **Mixing Network**: Submit user inputs
4. **Mixing Network**: Perform shuffle and decrypt permuted outputs
5. **Consortium**: Recover original user inputs using deanonymization secrets escrowed by mix peers

Several parameters for the consortium and the mixing network can be controlled via environment variables:

* `NUM_CONSORTIUMPEERS`: Number of peers in the consortium network (default = 4)
* `NUM_MIXPEERS`: Number of mix peers participating in the shuffle (default = 4)
* `NUM_INPUTS`: Number of user inputs submitted to the mixing network (default = 4)
* `NUM_MALICIOUS_DKG`: Number of malicious peers to simulate during the execution of the DKG protocols (consortium & mixing network, default = 0)
* `NUM_MALICIOUS_THRES`: Number of malicious peers to simulate during the threshold decryption steps (consortium & mixing network, default = 0)
* `SINGLE_RECOVERY`: If set, enables a special mode that allows the deanonymization of a single user (default = off)
* `SKIP_CONSORTIUM_DKG`: If set, use precomputed keys for the consortium (for up to 47 peers, default = off)

## Code Overview

| Module                         | Description                                                                                                                    |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| [zkps.py](zkps.py)             | Contains methods for producing ZKPoK's used in our proof construction.                                                         |
| [shuffle.py](shuffle.py)       | An implementation of Wikström's _Commitment-Consistent Proof of a Shuffle_, as well as our construction for a Proof of Escrow. |
| [elgamal.py](elgamal.py)       | Convenience functions for working with ElGamal Ciphertexts.                                                                    |
| [dkg.py](dkg.py)               | Implements the protocol for distributed key generation and threshold decryption (based on ElGamal).                            |
| [mixnet.py](mixnet.py)         | Protocol logic for the mix peers.                                                                                              |
| [consortium.py](consortium.py) | Protocol logic for the consortium.                                                                                             |
| [settings.py](settings.py)     | Contains public cryptographic parameters shared by the consortium & mix peers.                                                 |

The communication with and between peers is handled by the modules [peer.py](peer.py), [mixnet_web.py](mixnet_web.py) 
and [consortium_web.py](consortium_web.py). A CLI tool provided in [mixnet_cli.py](mixnet_cli.py) aids in issuing commands and 
submitting input to the peers.

Additional scripts in [eval.py](eval.py), [aggregate.py](aggregate.py) and [plot.py](plot.py) were used to run evaluations, 
aggregate timing data and generate plots for different configurations.

## License

[![CC BY 4.0][cc-by-shield]][cc-by]

This work is licensed under a
[Creative Commons Attribution 4.0 International License][cc-by].

[![CC BY 4.0][cc-by-image]][cc-by]

[cc-by]: http://creativecommons.org/licenses/by/4.0/
[cc-by-image]: https://i.creativecommons.org/l/by/4.0/88x31.png
[cc-by-shield]: https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg
