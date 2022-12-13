from dataclasses import dataclass
from typing import Dict

import dns.enum
from dns.dnssectypes import Algorithm


class Requirement(dns.enum.IntEnum):
    MUST_NOT = -2
    NOT_RECOMMENDED = -1
    MAY = 0
    RECOMMENDED = 1
    MUST = 2


@dataclass(frozen=True)
class AlgorithmRequirement:
    signing: Requirement
    validation: Requirement


AlgorithmPolicy = Dict[Algorithm, AlgorithmRequirement]


RFC_8624_POLICY = {
    Algorithm.RSAMD5: AlgorithmRequirement(
        signing=Requirement.MUST_NOT, validation=Requirement.MUST_NOT
    ),
    Algorithm.DSA: AlgorithmRequirement(
        signing=Requirement.MUST_NOT, validation=Requirement.MUST_NOT
    ),
    Algorithm.RSASHA1: AlgorithmRequirement(
        signing=Requirement.NOT_RECOMMENDED, validation=Requirement.MUST
    ),
    Algorithm.DSANSEC3SHA1: AlgorithmRequirement(
        signing=Requirement.MUST_NOT, validation=Requirement.MUST_NOT
    ),
    Algorithm.RSASHA1NSEC3SHA1: AlgorithmRequirement(
        signing=Requirement.NOT_RECOMMENDED, validation=Requirement.MUST
    ),
    Algorithm.RSASHA256: AlgorithmRequirement(
        signing=Requirement.MUST, validation=Requirement.MUST
    ),
    Algorithm.RSASHA512: AlgorithmRequirement(
        signing=Requirement.NOT_RECOMMENDED, validation=Requirement.MUST
    ),
    Algorithm.ECCGOST: AlgorithmRequirement(
        signing=Requirement.MUST_NOT, validation=Requirement.MAY
    ),
    Algorithm.ECDSAP256SHA256: AlgorithmRequirement(
        signing=Requirement.MUST, validation=Requirement.MUST
    ),
    Algorithm.ECDSAP384SHA384: AlgorithmRequirement(
        signing=Requirement.MAY, validation=Requirement.RECOMMENDED
    ),
    Algorithm.ED25519: AlgorithmRequirement(
        signing=Requirement.RECOMMENDED, validation=Requirement.RECOMMENDED
    ),
    Algorithm.ED448: AlgorithmRequirement(
        signing=Requirement.MAY, validation=Requirement.RECOMMENDED
    ),
}
