// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/AirdropManager.sol";
import "../contracts/MerkleDistributor.sol";
import "../contracts/ParticipationOracle.sol";
import "../contracts/interfaces/IParticipationOracle.sol";
import "../contracts/interfaces/IVerifier.sol";

contract MockOracle is IParticipationOracle {
    function getParticipationScore(address user) external pure override returns (uint256) {
        if (user == address(0)) return 0;
        return 9000; // fixed high score
    }
}

contract MockVerifier is IVerifier {
    function verify(bytes calldata /*proof*/) external pure override returns (bool) {
        return true;
    }
}

contract AirdropManagerTest is Test {
    AirdropManager manager;
    MerkleDistributor distributor;
    MockOracle oracle;
    MockVerifier verifier;

    address owner = address(this);
    address user = address(0xBEEF);
    bytes32 merkleRoot = 0x9c3df1527e7681b06fc3121d18d709ecb7c5d212e4358b1106d48f142ffce29f;

    function setUp() public {
        oracle = new MockOracle();
        verifier = new MockVerifier();
        distributor = new MerkleDistributor(merkleRoot);
        manager = new AirdropManager(address(distributor), address(oracle), address(verifier));

        distributor.transferOwnership(address(manager));
    }

    function testSetupCorrect() public {
        assertEq(address(manager.oracle()), address(oracle));
        assertEq(address(manager.verifier()), address(verifier));
        assertEq(address(manager.distributor()), address(distributor));
    }

    function testClaimSuccess() public {
        bytes32 ;
        proof[0] = bytes32("0x01");
        proof[1] = bytes32("0x02");

        vm.prank(address(manager));
        distributor.setClaimed(0); // simulate internal state

        vm.prank(user);
        bool success = manager.claim(0, user, 1 ether, proof, "zkProof");
        assertTrue(success);
    }

    function testRevertOnZeroScore() public {
        vm.prank(address(manager));
        distributor.setClaimed(1); // dummy set for setup

        vm.expectRevert("Participation score too low");
        manager.claim(1, address(0), 1 ether, new bytes32 , "zkProof");
    }

    function testInvalidProofFails() public {
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.verify.selector, abi.encode("invalid")),
            abi.encode(false)
        );

        vm.expectRevert("Invalid ZK proof");
        manager.claim(0, user, 1 ether, new bytes32 , "invalid");
    }

    function testFuzzClaimEdgeCases(uint256 amount) public {
        vm.assume(amount > 0 && amount < 1e30);

        bytes32 ;
        dummyProof[0] = bytes32("proof");

        vm.prank(address(manager));
        distributor.setClaimed(2);

        vm.prank(user);
        manager.claim(2, user, amount, dummyProof, "zkProof");
    }

    function testOnlyOnceClaimable() public {
        bytes32 ;
        dummyProof[0] = bytes32("proof");

        vm.prank(user);
        manager.claim(0, user, 1 ether, dummyProof, "zkProof");

        vm.expectRevert("Drop already claimed.");
        manager.claim(0, user, 1 ether, dummyProof, "zkProof");
    }

    function testStorageInvariants() public {
        // Check manager roles and pointers
        assertEq(manager.owner(), owner);
        assertTrue(address(manager.oracle()) != address(0));
        assertTrue(address(manager.distributor()) != address(0));
    }
}
