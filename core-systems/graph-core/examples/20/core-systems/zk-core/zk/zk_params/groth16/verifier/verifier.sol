// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [uint256(0x1800deef121f1e76403d8889f0e38b2fc8b58e85b9e77e1ef360c1a1a77a1d8e), 
             uint256(0x198e9393920d483a7260bfb731fb5db87c9f810e16cb0462e30c55c1a14aa34b)],
            [uint256(0x090689d0585ff1b3dcf8e6b88f0db8a1e3e3cf57478b0c7e3d2d7ed3e4f8c372), 
             uint256(0x12c85ea5db8c6deb32fcf7c01d0d7db9d35cc4c36d35dc42e66cf6d02e51a4a4)]
        );
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q_mod() - (p.Y % q_mod()));
    }

    function addition(G1Point memory p1, G1Point memory p2)
        internal view returns (G1Point memory r)
    {
        uint256[4] memory input = [p1.X, p1.Y, p2.X, p2.Y];
        bool success;
        assembly {
            success := staticcall(gas(), 6, input, 0x80, r, 0x40)
        }
        require(success, "Pairing: addition failed");
    }

    function scalar_mul(G1Point memory p, uint256 s)
        internal view returns (G1Point memory r)
    {
        uint256[3] memory input = [p.X, p.Y, s];
        bool success;
        assembly {
            success := staticcall(gas(), 7, input, 0x60, r, 0x40)
        }
        require(success, "Pairing: scalar_mul failed");
    }

    function pairing(
        G1Point[] memory p1,
        G2Point[] memory p2
    ) internal view returns (bool) {
        require(p1.length == p2.length, "Pairing: length mismatch");

        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(gas(), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }
        require(success, "Pairing: pairing check failed");
        return out[0] != 0;
    }

    function q_mod() internal pure returns (uint256) {
        return 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    }
}

contract Verifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(1, 2);
        vk.beta2 = Pairing.P2();
        vk.gamma2 = Pairing.P2();
        vk.delta2 = Pairing.P2();

        vk.IC = new Pairing.G1Point ;
        vk.IC[0] = Pairing.G1Point(1, 2); // vk.IC[0]
        vk.IC[1] = Pairing.G1Point(3, 4); // vk.IC[1]
    }

    function verify(uint[] memory input, Proof memory proof) public view returns (bool) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "Verifier: invalid input length");

        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint256 i = 0; i < input.length; i++) {
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.IC[0]);

        Pairing.G1Point ;
        Pairing.G2Point ;

        p1[0] = Pairing.negate(proof.A);
        p2[0] = proof.B;

        p1[1] = vk.alfa1;
        p2[1] = vk.beta2;

        p1[2] = vk_x;
        p2[2] = vk.gamma2;

        p1[3] = proof.C;
        p2[3] = vk.delta2;

        return Pairing.pairing(p1, p2);
    }

    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input
    ) public view returns (bool) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        return verify(input, proof);
    }
}
