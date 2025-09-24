// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface IGovernanceTarget {
    function executeProposal(bytes calldata data) external;
}

contract GovernanceModule is AccessControl {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ECDSA for bytes32;

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    struct Proposal {
        address target;
        bytes data;
        uint256 deadline;
        uint256 approvals;
        uint256 rejections;
        bool executed;
        mapping(address => bool) voters;
    }

    mapping(bytes32 => Proposal) private proposals;
    EnumerableSet.Bytes32Set private proposalIds;

    uint256 public quorum;
    uint256 public duration;
    address public signer; // off-chain permit signer (e.g. from Telegram or L2)

    event ProposalCreated(bytes32 indexed id, address proposer, address target, uint256 deadline);
    event ProposalVoted(bytes32 indexed id, address voter, bool support);
    event ProposalExecuted(bytes32 indexed id, address executor);

    modifier onlyActive(bytes32 id) {
        require(proposalIds.contains(id), "Invalid proposal");
        require(!proposals[id].executed, "Already executed");
        require(block.timestamp <= proposals[id].deadline, "Expired");
        _;
    }

    constructor(uint256 _quorum, uint256 _duration, address _signer) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(PROPOSER_ROLE, msg.sender);
        _setupRole(EXECUTOR_ROLE, msg.sender);

        quorum = _quorum;
        duration = _duration;
        signer = _signer;
    }

    function createProposal(address target, bytes calldata data) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes32 id = keccak256(abi.encode(target, data, block.timestamp, msg.sender));
        require(!proposalIds.contains(id), "Already exists");

        Proposal storage p = proposals[id];
        p.target = target;
        p.data = data;
        p.deadline = block.timestamp + duration;

        proposalIds.add(id);
        emit ProposalCreated(id, msg.sender, target, p.deadline);
        return id;
    }

    function vote(bytes32 id, bool support) external onlyActive(id) {
        Proposal storage p = proposals[id];
        require(!p.voters[msg.sender], "Already voted");

        p.voters[msg.sender] = true;
        if (support) {
            p.approvals++;
        } else {
            p.rejections++;
        }

        emit ProposalVoted(id, msg.sender, support);
    }

    function voteWithPermit(bytes32 id, bool support, bytes calldata signature) external onlyActive(id) {
        bytes32 digest = keccak256(abi.encodePacked(id, support, msg.sender)).toEthSignedMessageHash();
        require(digest.recover(signature) == signer, "Invalid signature");

        Proposal storage p = proposals[id];
        require(!p.voters[msg.sender], "Already voted");
        p.voters[msg.sender] = true;

        if (support) {
            p.approvals++;
        } else {
            p.rejections++;
        }

        emit ProposalVoted(id, msg.sender, support);
    }

    function execute(bytes32 id) external onlyRole(EXECUTOR_ROLE) onlyActive(id) {
        Proposal storage p = proposals[id];
        require(p.approvals >= quorum, "Not enough approvals");

        IGovernanceTarget(p.target).executeProposal(p.data);
        p.executed = true;
        emit ProposalExecuted(id, msg.sender);
    }

    // View helpers
    function getProposal(bytes32 id)
        external
        view
        returns (address target, uint256 deadline, uint256 approvals, uint256 rejections, bool executed)
    {
        Proposal storage p = proposals[id];
        return (p.target, p.deadline, p.approvals, p.rejections, p.executed);
    }

    function isVoter(bytes32 id, address account) external view returns (bool) {
        return proposals[id].voters[account];
    }

    function listProposals() external view returns (bytes32[] memory) {
        return proposalIds.values();
    }

    // Admin
    function setQuorum(uint256 newQuorum) external onlyRole(DEFAULT_ADMIN_ROLE) {
        quorum = newQuorum;
    }

    function setSigner(address newSigner) external onlyRole(DEFAULT_ADMIN_ROLE) {
        signer = newSigner;
    }

    function setDuration(uint256 newDuration) external onlyRole(DEFAULT_ADMIN_ROLE) {
        duration = newDuration;
    }
}
