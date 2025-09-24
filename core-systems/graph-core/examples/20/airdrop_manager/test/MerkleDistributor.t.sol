// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/MerkleDistributor.sol";

contract MerkleDistributorTest is Test {
    MerkleDistributor distributor;

    address recipient = address(0x1234);
    bytes32 constant LEAF = keccak256(abi.encodePacked(uint256(0), recipient, uint256(100 ether)));
    bytes32[] proof;
    bytes32 root;

    function setUp() public {
        root = computeRoot(LEAF);
        distributor = new MerkleDistributor(root);
        proof = generateProof(LEAF);
    }

    function testInitialState() public {
        assertEq(distributor.merkleRoot(), root);
        assertFalse(distributor.isClaimed(0));
    }

    function testClaimSuccess() public {
        vm.expectEmit(true, true, false, true);
        emit MerkleDistributor.Claimed(0, recipient, 100 ether);

        distributor.claim(0, recipient, 100 ether, proof);
        assertTrue(distributor.isClaimed(0));
    }

    function testDoubleClaimFails() public {
        distributor.claim(0, recipient, 100 ether, proof);
        vm.expectRevert("Drop already claimed.");
        distributor.claim(0, recipient, 100 ether, proof);
    }

    function testWrongAmountFails() public {
        vm.expectRevert("Invalid proof.");
        distributor.claim(0, recipient, 200 ether, proof);
    }

    function testWrongIndexFails() public {
        vm.expectRevert("Invalid proof.");
        distributor.claim(1, recipient, 100 ether, proof);
    }

    function testWrongRecipientFails() public {
        vm.expectRevert("Invalid proof.");
        distributor.claim(0, address(0xDEAD), 100 ether, proof);
    }

    function testFuzzClaim(uint256 amount, uint256 index) public {
        vm.assume(amount > 0 && amount < 1e30);
        vm.assume(index != 0); // для предотвращения совпадения с валидным

        bytes32 bogusLeaf = keccak256(abi.encodePacked(index, recipient, amount));
        bytes32[] memory bogusProof = generateProof(bogusLeaf);

        vm.expectRevert("Invalid proof.");
        distributor.claim(index, recipient, amount, bogusProof);
    }

    function computeRoot(bytes32 leaf) internal pure returns (bytes32) {
        // root = keccak(keccak(leaf + sibling) + ...)
        return keccak256(abi.encodePacked(leaf)); // simplify for single proof
    }

    function generateProof(bytes32 /*leaf*/) internal pure returns (bytes32[] memory) {
        bytes32 ;
        p[0] = bytes32(0); // mock sibling
        return p;
    }
}
