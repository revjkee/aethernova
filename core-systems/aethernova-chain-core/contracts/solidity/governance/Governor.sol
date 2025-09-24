// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// OpenZeppelin Governor 5.x modules
import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title AethernovaGovernor
/// @notice Production-grade Governor assembled from OpenZeppelin modules:
///         - Governor: core governance logic
///         - GovernorSettings: votingDelay, votingPeriod, proposalThreshold (governance-controlled)
///         - GovernorCountingSimple: For/Against/Abstain counting
///         - GovernorVotes: voting power from an IVotes token (e.g., ERC20Votes)
///         - GovernorVotesQuorumFraction: quorum as a fraction of total supply
///         - GovernorTimelockControl: queue/execute via TimelockController
contract AethernovaGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl
{
    /// @param token IVotes-compatible token used for voting (e.g., ERC20Votes)
    /// @param timelock TimelockController instance that will queue/execute successful proposals
    /// @param initialVotingDelay Delay before voting starts (units depend on Governor clock; default blocks)
    /// @param initialVotingPeriod Duration of voting (same units as clock)
    /// @param initialProposalThreshold Minimum voting power to create proposals
    /// @param quorumNumeratorValue Quorum numerator (over denominator, usually 100)
    constructor(
        IVotes token,
        TimelockController timelock,
        uint256 initialVotingDelay,
        uint256 initialVotingPeriod,
        uint256 initialProposalThreshold,
        uint256 quorumNumeratorValue
    )
        Governor("Aethernova Governor")
        GovernorSettings(
            initialVotingDelay,
            initialVotingPeriod,
            initialProposalThreshold
        )
        GovernorVotes(token)
        GovernorVotesQuorumFraction(quorumNumeratorValue)
        GovernorTimelockControl(timelock)
    {}

    // --- Required overrides to compose multiple Governor extensions ---

    /// @dev Quorum as fraction of total supply at a given block (from GovernorVotesQuorumFraction)
    function quorum(uint256 blockNumber)
        public
        view
        override(Governor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(blockNumber);
    }

    /// @dev Proposal state considering timelock workflow
    function state(uint256 proposalId)
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (ProposalState)
    {
        return super.state(proposalId);
    }

    /// @dev Execute proposal through TimelockController
    function _execute(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    )
        internal
        override(Governor, GovernorTimelockControl)
    {
        super._execute(proposalId, targets, values, calldatas, descriptionHash);
    }

    /// @dev Cancel proposal considering both Governor and Timelock rules
    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    )
        internal
        override(Governor, GovernorTimelockControl)
        returns (uint256)
    {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    /// @dev Proposal threshold comes from GovernorSettings
    function proposalThreshold()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.proposalThreshold();
    }

    /// @dev ERC165 support across multiple parents
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
