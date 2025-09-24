// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TON↔zkVM Bridge Contract
/// @author TeslaAI Genesis
/// @notice Поддерживает двухстороннюю связь между TON и zkVM (EVM), включая zk-доказательства, permit и безопасность шлюза.

interface IZKVerifier {
    function verifyProof(bytes calldata zkProof, bytes32 commitment) external view returns (bool);
}

interface ITONGateway {
    function receiveTONTransfer(bytes calldata tonPayload, bytes calldata zkProof) external;
}

contract TONBridge {
    address public admin;
    IZKVerifier public zkVerifier;
    mapping(bytes32 => bool) public processedCommitments;

    event TONImported(address indexed recipient, uint256 amount, bytes32 commitment);
    event TONExportRequested(address indexed sender, string tonAddress, uint256 amount, bytes32 id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized");
        _;
    }

    constructor(address _verifier) {
        admin = msg.sender;
        zkVerifier = IZKVerifier(_verifier);
    }

    /// @notice Обработка прихода TON-средств (через zk-доказательства)
    function importTON(bytes calldata zkProof, bytes32 commitment, address recipient, uint256 amount) external {
        require(!processedCommitments[commitment], "Commitment already used");
        require(zkVerifier.verifyProof(zkProof, commitment), "Invalid ZK proof");

        processedCommitments[commitment] = true;
        payable(recipient).transfer(amount);

        emit TONImported(recipient, amount, commitment);
    }

    /// @notice Запрос на экспорт в TON (обработка offchain-мостом)
    function requestExport(string calldata tonAddress) external payable {
        require(msg.value > 0, "Amount must be > 0");
        bytes32 id = keccak256(abi.encodePacked(msg.sender, tonAddress, msg.value, block.timestamp));
        emit TONExportRequested(msg.sender, tonAddress, msg.value, id);
    }

    /// @notice Аварийное обновление верификатора
    function updateVerifier(address _verifier) external onlyAdmin {
        zkVerifier = IZKVerifier(_verifier);
    }

    /// @notice Вывод средств в экстренных ситуациях
    function emergencyWithdraw(address to, uint256 amount) external onlyAdmin {
        payable(to).transfer(amount);
    }

    receive() external payable {}
}
