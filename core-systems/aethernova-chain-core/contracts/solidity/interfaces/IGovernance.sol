// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IGovernance
/// @notice Industrial-grade interface for on-chain governance (proposal lifecycle,
///         voting, timelock queue/execute, thresholds, quorum and snapshots).
/// @dev    This interface is implementation-agnostic. Implementations MAY rely on
///         ERC20Votes/IVotes-like token, checkpoints, or custom voting power logic.
interface IGovernance {
    // -------------------------------------------------------------------------
    //                                Types
    // -------------------------------------------------------------------------

    /// @notice Voting options (simple plurality with abstain).
    /// @dev    Implementations MAY extend via additional counting logic internally.
    enum VoteType {
        Against, // 0
        For,     // 1
        Abstain  // 2
    }

    /// @notice Immutable data identifying a proposal's action set.
    /// @dev    Targets, values and calldatas are positional and MUST be equal length.
    struct ProposalAction {
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
    }

    /// @notice Snapshot-based vote receipt for an account.
    struct Receipt {
        bool hasVoted;
        uint8 supportRaw;    // cast as VoteType
        uint256 weight;      // voting weight used when voting
        string reason;       // optional; empty if not provided
    }

    /// @notice Lightweight ECDSA signature tuple for castVoteBySig.
    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Canonical proposal states.
    enum ProposalState {
        Pending,
        Active,
        Canceled,
        Defeated,
        Succeeded,
        Queued,
        Expired,
        Executed
    }

    // -------------------------------------------------------------------------
    //                                Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new proposal is created.
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address[] targets,
        uint256[] values,
        bytes[] calldatas,
        uint256 startBlock,
        uint256 endBlock,
        string description
    );

    /// @notice Emitted when a proposal is canceled.
    event ProposalCanceled(uint256 indexed proposalId);

    /// @notice Emitted when a proposal is queued for timelock execution.
    event ProposalQueued(uint256 indexed proposalId, uint256 eta);

    /// @notice Emitted when a proposal is executed.
    event ProposalExecuted(uint256 indexed proposalId);

    /// @notice Emitted when a vote is cast.
    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        uint8 support,       // VoteType
        uint256 weight,
        string reason
    );

    /// @notice Governance parameter changes (optional for implementations).
    event VotingDelaySet(uint256 oldValue, uint256 newValue);
    event VotingPeriodSet(uint256 oldValue, uint256 newValue);
    event ProposalThresholdSet(uint256 oldValue, uint256 newValue);

    // -------------------------------------------------------------------------
    //                                Errors
    // -------------------------------------------------------------------------

    error GovInvalidArrayLengths();
    error GovUnknownProposal(uint256 proposalId);
    error GovUnexpectedState(uint256 proposalId, ProposalState expected, ProposalState actual);
    error GovAlreadyQueued(uint256 proposalId);
    error GovNotQueued(uint256 proposalId);
    error GovSignatureExpired();
    error GovAlreadyVoted(address voter, uint256 proposalId);
    error GovInsufficientProposerVotes(address proposer, uint256 votes, uint256 threshold);

    // -------------------------------------------------------------------------
    //                         Human-readable metadata
    // -------------------------------------------------------------------------

    /// @notice Name of the governance instance (e.g., protocol name).
    function name() external view returns (string memory);

    /// @notice Free-form counting mode description (for UIs/analytics).
    /// @dev    SHOULD describe how votes are tallied, e.g. "support=bravo,quorum=for,params=threshold".
    function COUNTING_MODE() external view returns (string memory);

    // -------------------------------------------------------------------------
    //                        Governance configuration
    // -------------------------------------------------------------------------

    /// @notice Minimum voting power required to create a proposal.
    function proposalThreshold() external view returns (uint256);

    /// @notice Voting delay in blocks before a proposal becomes Active.
    function votingDelay() external view returns (uint256);

    /// @notice Voting period in blocks while a proposal is Active.
    function votingPeriod() external view returns (uint256);

    /// @notice Quorum required at a given blockNumber (units of voting power).
    function quorum(uint256 blockNumber) external view returns (uint256);

    // -------------------------------------------------------------------------
    //                           Proposal lifecycle
    // -------------------------------------------------------------------------

    /// @notice Returns the state of a proposal.
    function state(uint256 proposalId) external view returns (ProposalState);

    /// @notice Derives the keccak256 hash of the proposal description string.
    /// @dev    Provided for convenience; implementations may store/compute as needed.
    function hashProposalDescription(string calldata description) external pure returns (bytes32);

    /// @notice Propose a new action set.
    /// @param  targets   Call targets.
    /// @param  values    ETH values for each call.
    /// @param  calldatas Calldata bytes for each call.
    /// @param  description Human-readable proposal text.
    /// @return proposalId Unique id of the newly created proposal.
    function propose(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata calldatas,
        string calldata description
    ) external returns (uint256 proposalId);

    /// @notice Block at which voting starts for a proposal.
    function proposalSnapshot(uint256 proposalId) external view returns (uint256);

    /// @notice Block at which voting ends for a proposal.
    function proposalDeadline(uint256 proposalId) external view returns (uint256);

    /// @notice Address that created the proposal.
    function proposalProposer(uint256 proposalId) external view returns (address);

    /// @notice Return immutable action set of the proposal.
    function proposalActions(uint256 proposalId)
        external
        view
        returns (address[] memory targets, uint256[] memory values, bytes[] memory calldatas);

    /// @notice Cancel a proposal (e.g., if proposer drops under threshold).
    function cancel(uint256 proposalId) external;

    // -------------------------------------------------------------------------
    //                                 Voting
    // -------------------------------------------------------------------------

    /// @notice Returns past voting power of `account` at `blockNumber`.
    /// @dev    Implementations MAY source from token checkpoints or custom logic.
    function getVotes(address account, uint256 blockNumber) external view returns (uint256);

    /// @notice Returns whether `account` has voted on `proposalId`.
    function hasVoted(uint256 proposalId, address account) external view returns (bool);

    /// @notice Returns stored receipt (if any) for `account` on `proposalId`.
    function getReceipt(uint256 proposalId, address account) external view returns (Receipt memory);

    /// @notice Cast a vote (Against/For/Abstain). Returns voting weight counted.
    function castVote(uint256 proposalId, uint8 support) external returns (uint256);

    /// @notice Cast a vote with reason string.
    function castVoteWithReason(uint256 proposalId, uint8 support, string calldata reason)
        external
        returns (uint256);

    /// @notice Cast a vote by ECDSA signature (off-chain signed ballot).
    /// @dev    The signed payload SHOULD encode {proposalId, support, nonce, expiry}.
    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        address voter,
        Signature calldata sig,
        uint256 nonce,
        uint256 expiry
    ) external returns (uint256);

    // -------------------------------------------------------------------------
    //                           Queue & Execute (Timelock)
    // -------------------------------------------------------------------------

    /// @notice Queue a succeeded proposal for execution after timelock delay.
    /// @return eta Timestamp after which the proposal may be executed.
    function queue(uint256 proposalId) external returns (uint256 eta);

    /// @notice Execute a queued proposal's action set.
    /// @dev    Implementations MAY be payable if actions transfer ETH.
    function execute(uint256 proposalId) external payable;

    /// @notice ETA returned by queue(). Zero if not queued.
    function proposalEta(uint256 proposalId) external view returns (uint256);

    // -------------------------------------------------------------------------
    //                         Administrative (optional)
    // -------------------------------------------------------------------------

    /// @notice Set voting delay in blocks.
    function setVotingDelay(uint256 newVotingDelay) external;

    /// @notice Set voting period in blocks.
    function setVotingPeriod(uint256 newVotingPeriod) external;

    /// @notice Set proposal threshold in voting power units.
    function setProposalThreshold(uint256 newThreshold) external;
}
