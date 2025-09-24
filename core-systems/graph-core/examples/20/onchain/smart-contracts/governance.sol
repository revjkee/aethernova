// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";

/// @title TeslaAI DAO Governance Contract
/// @notice Контракт управления DAO с поддержкой голосования токенами и кворума
contract Governance is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction
{
    /// @notice Конструктор контракта
    /// @param _token Адрес токена с возможностью делегирования голосов (ERC20Votes)
    constructor(IVotes _token)
        Governor("TeslaAI_Governance")
        GovernorSettings(
            1 /* delay в блоках */,
            45818 /* период голосования ~1 неделя при 15с блоке */,
            100000e18 /* минимальное количество голосов для предложения */
        )
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(4) // кворум 4%
    {}

    /// @notice Возвращает описание голосования (принято по умолчанию)
    function votingDelay() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.votingDelay();
    }

    /// @notice Возвращает продолжительность голосования
    function votingPeriod() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.votingPeriod();
    }

    /// @notice Минимальный порог голосов для создания предложения
    function proposalThreshold() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.proposalThreshold();
    }

    /// @notice Обработка голосования (подсчет "за", "против", "воздержался")
    function quorum(uint256 blockNumber) public view override(Governor, GovernorVotesQuorumFraction) returns (uint256) {
        return super.quorum(blockNumber);
    }

    /// @notice Проверка, разрешено ли голосование в данный момент
    function state(uint256 proposalId) public view override(Governor) returns (ProposalState) {
        return super.state(proposalId);
    }

    /// @notice Внутренняя функция для выполнения решения после успешного голосования
    function _execute(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor) {
        super._execute(proposalId, targets, values, calldatas, descriptionHash);
    }

    /// @notice Внутренняя функция отмены предложения
    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    /// @notice Внутренняя функция для проверки прав на выполнение
    function _executor() internal view override(Governor) returns (address) {
        return super._executor();
    }

    /// @notice Вспомогательная функция для поддержки интерфейсов
    function supportsInterface(bytes4 interfaceId) public view override(Governor) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
