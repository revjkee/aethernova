// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * AirdropManager — промышленный менеджер мульти-кампаний для ERC-20:
 * - Поддержка нескольких кампаний (каждая со своим токеном, merkleRoot и окном времени)
 * - Merkle-проверка листа вида keccak256(abi.encodePacked(index, account, amount))
 * - Одноразовый клейм по индексу через битовую карту (BitMaps)
 * - Фандинг кампаний с учётом общего выделения и учёта фактически внесённых средств
 * - Пауза (Pausable) и защита от реэнтранси (ReentrancyGuard)
 * - Роли доступа (AccessControl): DEFAULT_ADMIN_ROLE и MANAGER_ROLE
 * - Отзыв кампании (revocable) и возврат невыкупленных токенов после end/отзыва
 * - События для полного аудита
 *
 * Требования к окружению:
 *   OpenZeppelin Contracts (v5+):
 *     - token/ERC20/IERC20.sol
 *     - token/ERC20/utils/SafeERC20.sol
 *     - access/AccessControl.sol
 *     - utils/Pausable.sol
 *     - utils/ReentrancyGuard.sol
 *     - utils/cryptography/MerkleProof.sol
 *     - utils/structs/BitMaps.sol
 */

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";

contract AirdropManager is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using BitMaps for BitMaps.BitMap;

    // ------------------------- РОЛИ -------------------------

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    // ------------------------- ОШИБКИ -----------------------

    error InvalidToken();
    error InvalidTimeWindow();
    error CampaignNotFound();
    error CampaignActive();
    error CampaignInactive();
    error CampaignRevoked();
    error CampaignNotRevocable();
    error AlreadyClaimed();
    error ProofInvalid();
    error ZeroAmount();
    error FundingExceeded();
    error NotEnoughFunds();
    error NotStarted();
    error Ended();
    error NotAuthorized();
    error NothingToRecover();

    // ------------------------- СОБЫТИЯ ----------------------

    event CampaignCreated(
        uint256 indexed campaignId,
        address indexed token,
        bytes32 merkleRoot,
        uint64 start,
        uint64 end,
        bool revocable,
        address indexed createdBy,
        uint96 totalAllocated
    );

    event CampaignFunded(
        uint256 indexed campaignId,
        address indexed funder,
        uint96 amount,
        uint96 totalFunded
    );

    event Claimed(
        uint256 indexed campaignId,
        uint256 indexed index,
        address indexed account,
        uint96 amount
    );

    event MerkleRootUpdated(
        uint256 indexed campaignId,
        bytes32 oldRoot,
        bytes32 newRoot,
        address indexed updater
    );

    event CampaignRevokedEvent(
        uint256 indexed campaignId,
        address indexed revoker
    );

    event UnclaimedRecovered(
        uint256 indexed campaignId,
        address indexed to,
        uint96 amount
    );

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // ------------------------- ДАННЫЕ -----------------------

    struct Campaign {
        address token;          // адрес ERC-20
        bytes32 merkleRoot;     // корень Merkle
        uint64  start;          // unix start (включительно)
        uint64  end;            // unix end (исключительно)
        bool    revocable;      // можно ли отзывать/обновлять корень до старта
        bool    revoked;        // флаг отзыва
        address funder;         // первый пополнивший (для удобства учёта)
        uint96  totalAllocated; // общий лимит распределения (по листу)
        uint96  totalFunded;    // сколько реально заведено в контракт для кампании
        uint96  totalClaimed;   // сколько выкуплено
    }

    uint256 public campaignCount;
    mapping(uint256 => Campaign) private _campaigns;
    mapping(uint256 => BitMaps.BitMap) private _claimedBitMaps; // index -> claimed

    // ------------------------- КОНСТРУКТОР ------------------

    constructor(address admin, address manager) {
        if (admin == address(0)) revert NotAuthorized();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        if (manager != address(0)) {
            _grantRole(MANAGER_ROLE, manager);
        }
    }

    // ------------------------- МОДИФИКАТОРЫ -----------------

    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyManager() {
        if (!hasRole(MANAGER_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    // ------------------------- АДМИН-КОНТРОЛЬ ----------------

    function pause() external onlyAdmin {
        _pause();
        emit Paused(msg.sender);
    }

    function unpause() external onlyAdmin {
        _unpause();
        emit Unpaused(msg.sender);
    }

    // ------------------------- КАМПАНИИ ----------------------

    function getCampaign(uint256 campaignId) external view returns (Campaign memory) {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        return _campaigns[campaignId];
    }

    function isClaimed(uint256 campaignId, uint256 index) public view returns (bool) {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        return _claimedBitMaps[campaignId].get(index);
    }

    /**
     * Создать кампанию.
     * Требование: end > start, token != 0, totalAllocated > 0.
     * revocable: разрешает до старта обновлять merkleRoot либо отзывать кампанию.
     */
    function createCampaign(
        address token,
        bytes32 merkleRoot,
        uint64 start,
        uint64 end,
        uint96 totalAllocated,
        bool revocable
    ) external onlyManager whenNotPaused returns (uint256 campaignId) {
        if (token == address(0)) revert InvalidToken();
        if (end <= start) revert InvalidTimeWindow();
        if (totalAllocated == 0) revert ZeroAmount();

        campaignId = ++campaignCount;
        _campaigns[campaignId] = Campaign({
            token: token,
            merkleRoot: merkleRoot,
            start: start,
            end: end,
            revocable: revocable,
            revoked: false,
            funder: address(0),
            totalAllocated: totalAllocated,
            totalFunded: 0,
            totalClaimed: 0
        });

        emit CampaignCreated(
            campaignId,
            token,
            merkleRoot,
            start,
            end,
            revocable,
            msg.sender,
            totalAllocated
        );
    }

    /**
     * Пополнить кампанию токенами (transferFrom).
     * Требуется предварительный approve на адрес этого контракта.
     * totalFunded не может превышать totalAllocated.
     */
    function fundCampaign(uint256 campaignId, uint96 amount) external whenNotPaused {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        if (amount == 0) revert ZeroAmount();

        Campaign storage c = _campaigns[campaignId];
        if (block.timestamp >= c.end) revert Ended();
        if (c.revoked) revert CampaignRevoked();

        unchecked {
            uint96 newTotal = c.totalFunded + amount;
            if (newTotal < c.totalFunded || newTotal > c.totalAllocated) revert FundingExceeded();
            c.totalFunded = newTotal;
        }

        if (c.funder == address(0)) {
            c.funder = msg.sender;
        }

        IERC20(c.token).safeTransferFrom(msg.sender, address(this), amount);
        emit CampaignFunded(campaignId, msg.sender, amount, c.totalFunded);
    }

    /**
     * Обновить merkleRoot до старта, если кампания revocable и не отозвана.
     */
    function updateMerkleRoot(uint256 campaignId, bytes32 newRoot) external onlyManager whenNotPaused {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        Campaign storage c = _campaigns[campaignId];

        if (!c.revocable) revert CampaignNotRevocable();
        if (c.revoked) revert CampaignRevoked();
        if (block.timestamp >= c.start) revert CampaignActive();

        bytes32 old = c.merkleRoot;
        c.merkleRoot = newRoot;
        emit MerkleRootUpdated(campaignId, old, newRoot, msg.sender);
    }

    /**
     * Отозвать кампанию (дальнейшие клеймы невозможны).
     * Доступно только для revocable кампаний; можно вызывать в любой момент.
     */
    function revokeCampaign(uint256 campaignId) external onlyManager whenNotPaused {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        Campaign storage c = _campaigns[campaignId];
        if (!c.revocable) revert CampaignNotRevocable();
        if (c.revoked) revert CampaignRevoked();

        c.revoked = true;
        emit CampaignRevokedEvent(campaignId, msg.sender);
    }

    // ------------------------- КЛЕЙМ ------------------------

    /**
     * Клейм по Merkle-доказательству.
     * Лист: keccak256(abi.encodePacked(index, account, amount))
     */
    function claim(
        uint256 campaignId,
        uint256 index,
        address account,
        uint96 amount,
        bytes32[] calldata merkleProof
    ) external nonReentrant whenNotPaused {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        if (amount == 0) revert ZeroAmount();

        Campaign storage c = _campaigns[campaignId];

        if (block.timestamp < c.start) revert NotStarted();
        if (block.timestamp >= c.end) revert Ended();
        if (c.revoked) revert CampaignRevoked();

        if (isClaimed(campaignId, index)) revert AlreadyClaimed();

        // Проверка proof
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        bool valid = MerkleProof.verify(merkleProof, c.merkleRoot, leaf);
        if (!valid) revert ProofInvalid();

        // Обновляем учёт
        unchecked {
            uint96 newClaimed = c.totalClaimed + amount;
            // переполнение или превышение totalAllocated недопустимо
            if (newClaimed < c.totalClaimed || newClaimed > c.totalAllocated) revert FundingExceeded();
            c.totalClaimed = newClaimed;
        }

        // Проверка фактического фонда под кампанию
        uint96 fundedLeft = c.totalFunded - c.totalClaimed + amount; // до вычета текущего перевода
        // fundedLeft = totalFunded - (newClaimed) + amount = totalFunded - (prevClaimed + amount) + amount = totalFunded - prevClaimed
        // фактически нам важно текущее доступное покрытие:
        uint256 available = IERC20(c.token).balanceOf(address(this));
        if (available < amount) revert NotEnoughFunds();

        // Фиксируем бит: клейм по индексу одноразовый
        _claimedBitMaps[campaignId].set(index);

        // Перевод
        IERC20(c.token).safeTransfer(account, amount);

        emit Claimed(campaignId, index, account, amount);
    }

    // ------------------------- ВОЗВРАТ НЕВЫКУПЛЕННОГО ------------------------

    /**
     * Возвратить невыкупленные токены после окончания окна или после отзыва.
     * Можно вызывать менеджером; получатель — произвольный адрес (например, фонд).
     */
    function recoverUnclaimed(uint256 campaignId, address to) external onlyManager nonReentrant {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        if (to == address(0)) revert InvalidToken();
        Campaign storage c = _campaigns[campaignId];

        // Разрешаем, если кампания закончилась или отозвана
        if (!(block.timestamp >= c.end || c.revoked)) revert CampaignActive();

        uint96 funded = c.totalFunded;
        uint96 claimed = c.totalClaimed;

        if (funded <= claimed) revert NothingToRecover();
        uint96 remainder = funded - claimed;

        // Обновляем totalFunded до фактически востребованного, чтобы не допустить двойной возврат
        c.totalFunded = claimed;

        IERC20(c.token).safeTransfer(to, remainder);
        emit UnclaimedRecovered(campaignId, to, remainder);
    }

    // ------------------------- УТИЛИТЫ БЕЗОПАСНОСТИ --------------------------

    /**
     * Аварийный вывод любых ERC-20, не закреплённых за кампанией, админом.
     * Не влияет на учёт кампаний.
     */
    function rescueERC20(address token, address to, uint256 amount) external onlyAdmin nonReentrant {
        if (token == address(0) || to == address(0)) revert InvalidToken();
        IERC20(token).safeTransfer(to, amount);
    }

    // ------------------------- VIEW/HELPERS ----------------------------------

    function campaignAvailableToRecover(uint256 campaignId) external view returns (uint256) {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        Campaign storage c = _campaigns[campaignId];
        if (c.totalFunded <= c.totalClaimed) return 0;
        return uint256(c.totalFunded - c.totalClaimed);
    }

    function campaignIsActive(uint256 campaignId) external view returns (bool) {
        if (campaignId == 0 || campaignId > campaignCount) revert CampaignNotFound();
        Campaign storage c = _campaigns[campaignId];
        return !c.revoked && block.timestamp >= c.start && block.timestamp < c.end;
    }
}
