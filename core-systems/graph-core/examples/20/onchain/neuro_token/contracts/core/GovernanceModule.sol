// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title GovernanceModule — модуль исполнения решений DAO
/// @notice Поддержка таймера, ролей, аудита, мультиисполнения и интеграции с AI
contract GovernanceModule is AccessControl {
    using EnumerableSet for EnumerableSet.UintSet;

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;         // исполнение не раньше этого времени
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    EnumerableSet.UintSet private pendingProposals;

    uint256 public delay = 1 days;
    uint256 public proposalCounter;

    event ProposalCreated(uint256 indexed id, address target, uint256 eta);
    event Executed(uint256 indexed id, address target, bool success);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROPOSER_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
    }

    /// @notice Создание предложения для исполнения (любое действие в сети)
    function propose(address target, uint256 value, bytes calldata data) external onlyRole(PROPOSER_ROLE) returns (uint256) {
        require(target != address(0), "Invalid target");

        uint256 id = ++proposalCounter;
        proposals[id] = Proposal({
            target: target,
            value: value,
            data: data,
            eta: block.timestamp + delay,
            executed: false
        });

        pendingProposals.add(id);
        emit ProposalCreated(id, target, proposals[id].eta);
        return id;
    }

    /// @notice Исполнение — только после ETA, только один раз
    function execute(uint256 id) external onlyRole(EXECUTOR_ROLE) {
        Proposal storage p = proposals[id];
        require(!p.executed, "Already executed");
        require(block.timestamp >= p.eta, "Too early");

        (bool success, ) = p.target.call{value: p.value}(p.data);
        require(success, "Execution failed");

        p.executed = true;
        pendingProposals.remove(id);
        emit Executed(id, p.target, success);
    }

    /// @notice Получить список активных ID предложений
    function getPending() external view returns (uint256[] memory) {
        return pendingProposals.values();
    }

    /// @notice Изменение задержки (только админ)
    function setDelay(uint256 newDelay) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delay = newDelay;
    }

    /// @notice Получить данные предложения
    function getProposal(uint256 id) external view returns (Proposal memory) {
        return proposals[id];
    }

    /// @notice Получить calldata для mint через Governance
    function encodeMint(address to, uint256 amount) external pure returns (bytes memory) {
        return abi.encodeWithSignature("mint(address,uint256)", to, amount);
    }

    receive() external payable {} // для приёма средств DAO
}
