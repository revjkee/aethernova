// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

interface IGovernanceModule {
    function createProposal(address target, bytes calldata data) external returns (bytes32);
}

contract DAOProposalFactory is AccessControl {
    using Counters for Counters.Counter;
    using ECDSA for bytes32;

    bytes32 public constant PROPOSAL_CREATOR_ROLE = keccak256("PROPOSAL_CREATOR_ROLE");

    IGovernanceModule public governanceModule;
    address public offchainSigner;

    Counters.Counter private _proposalCount;

    struct ProposalMetadata {
        bytes32 id;
        string title;
        string description;
        address target;
        uint256 timestamp;
        address proposer;
    }

    mapping(bytes32 => ProposalMetadata) public proposals;
    mapping(uint256 => bytes32) public indexToProposalId;

    event ProposalCreated(
        bytes32 indexed id,
        string title,
        address indexed proposer,
        address indexed target,
        uint256 timestamp
    );

    constructor(address _governanceModule, address _signer) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(PROPOSAL_CREATOR_ROLE, msg.sender);

        governanceModule = IGovernanceModule(_governanceModule);
        offchainSigner = _signer;
    }

    function create(
        address target,
        bytes calldata data,
        string calldata title,
        string calldata description
    ) external onlyRole(PROPOSAL_CREATOR_ROLE) returns (bytes32) {
        bytes32 id = governanceModule.createProposal(target, data);
        uint256 index = _proposalCount.current();

        proposals[id] = ProposalMetadata({
            id: id,
            title: title,
            description: description,
            target: target,
            timestamp: block.timestamp,
            proposer: msg.sender
        });

        indexToProposalId[index] = id;
        _proposalCount.increment();

        emit ProposalCreated(id, title, msg.sender, target, block.timestamp);
        return id;
    }

    function createWithPermit(
        address target,
        bytes calldata data,
        string calldata title,
        string calldata description,
        address sender,
        bytes calldata signature
    ) external returns (bytes32) {
        bytes32 digest = keccak256(abi.encodePacked(target, data, title, sender)).toEthSignedMessageHash();
        require(digest.recover(signature) == offchainSigner, "Invalid signature");

        bytes32 id = governanceModule.createProposal(target, data);
        uint256 index = _proposalCount.current();

        proposals[id] = ProposalMetadata({
            id: id,
            title: title,
            description: description,
            target: target,
            timestamp: block.timestamp,
            proposer: sender
        });

        indexToProposalId[index] = id;
        _proposalCount.increment();

        emit ProposalCreated(id, title, sender, target, block.timestamp);
        return id;
    }

    function getProposalByIndex(uint256 index) external view returns (ProposalMetadata memory) {
        bytes32 id = indexToProposalId[index];
        return proposals[id];
    }

    function totalProposals() external view returns (uint256) {
        return _proposalCount.current();
    }

    function updateSigner(address newSigner) external onlyRole(DEFAULT_ADMIN_ROLE) {
        offchainSigner = newSigner;
    }

    function updateGovernanceModule(address newModule) external onlyRole(DEFAULT_ADMIN_ROLE) {
        governanceModule = IGovernanceModule(newModule);
    }
}
