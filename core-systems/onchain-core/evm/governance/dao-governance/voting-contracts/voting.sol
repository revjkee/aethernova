// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DAO Voting Contract с ZK-rollup совместимостью
/// @notice Управляет голосованием по предложениям в DAO с проверками и подсчетом голосов
/// @dev Использует события, модификаторы и хранит состояния в маппингах для масштабируемости

contract Voting {
    enum VoteType { None, For, Against, Abstain }
    enum ProposalStatus { Pending, Active, Executed, Cancelled }

    struct Proposal {
        address proposer;
        string description;
        uint256 startBlock;
        uint256 endBlock;
        ProposalStatus status;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 votesAbstain;
        mapping(address => VoteType) votes;
    }

    mapping(uint256 => Proposal) private proposals;
    uint256 private proposalCount;

    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string description, uint256 startBlock, uint256 endBlock);
    event VoteCast(address indexed voter, uint256 indexed proposalId, VoteType vote);
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId);

    modifier onlyActiveProposal(uint256 proposalId) {
        require(proposals[proposalId].status == ProposalStatus.Active, "Proposal is not active");
        _;
    }

    modifier withinVotingPeriod(uint256 proposalId) {
        require(block.number >= proposals[proposalId].startBlock && block.number <= proposals[proposalId].endBlock, "Voting period ended or not started");
        _;
    }

    function createProposal(string calldata description, uint256 votingPeriodBlocks) external returns (uint256) {
        require(votingPeriodBlocks > 0, "Voting period must be positive");

        proposalCount++;
        Proposal storage p = proposals[proposalCount];
        p.proposer = msg.sender;
        p.description = description;
        p.startBlock = block.number;
        p.endBlock = block.number + votingPeriodBlocks;
        p.status = ProposalStatus.Active;

        emit ProposalCreated(proposalCount, msg.sender, description, p.startBlock, p.endBlock);
        return proposalCount;
    }

    function castVote(uint256 proposalId, VoteType vote) external onlyActiveProposal(proposalId) withinVotingPeriod(proposalId) {
        require(vote == VoteType.For || vote == VoteType.Against || vote == VoteType.Abstain, "Invalid vote");

        Proposal storage p = proposals[proposalId];
        require(p.votes[msg.sender] == VoteType.None, "Already voted");

        p.votes[msg.sender] = vote;
        if (vote == VoteType.For) {
            p.votesFor++;
        } else if (vote == VoteType.Against) {
            p.votesAgainst++;
        } else if (vote == VoteType.Abstain) {
            p.votesAbstain++;
        }

        emit VoteCast(msg.sender, proposalId, vote);
    }

    function executeProposal(uint256 proposalId) external onlyActiveProposal(proposalId) {
        Proposal storage p = proposals[proposalId];
        require(block.number > p.endBlock, "Voting still active");

        p.status = ProposalStatus.Executed;
        emit ProposalExecuted(proposalId);

        // Здесь должна быть логика исполнения решения (off-chain или через другой контракт)
    }

    function cancelProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(msg.sender == p.proposer, "Only proposer can cancel");
        require(p.status == ProposalStatus.Active, "Proposal not active");

        p.status = ProposalStatus.Cancelled;
        emit ProposalCancelled(proposalId);
    }

    function getProposal(uint256 proposalId) external view returns (
        address proposer,
        string memory description,
        uint256 startBlock,
        uint256 endBlock,
        ProposalStatus status,
        uint256 votesFor,
        uint256 votesAgainst,
        uint256 votesAbstain
    ) {
        Proposal storage p = proposals[proposalId];
        return (
            p.proposer,
            p.description,
            p.startBlock,
            p.endBlock,
            p.status,
            p.votesFor,
            p.votesAgainst,
            p.votesAbstain
        );
    }

    function getVote(uint256 proposalId, address voter) external view returns (VoteType) {
        return proposals[proposalId].votes[voter];
    }
}
