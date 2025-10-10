// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PrivateExt: Shield/Unshield gateway for ETH and ERC20
/// @notice Industrial-grade extension to integrate privacy layer with Aethernova chain.
/// @dev
///  - Supports ETH and ERC20 (optionally via EIP-2612 permit)
///  - Records commitments on shield; enforces nullifier uniqueness on unshield
///  - Fee accounting with recipient, pausability, roles, allowlist, reentrancy guard
///  - Proof verification delegated to external IVerifier
///
/// File path: aethernova-chain-core/contracts/solidity/tokens/PrivateExt.sol
contract PrivateExt is AccessControlLite, PausableLite, ReentrancyGuardLite {
    using SafeERC20 for IERC20;

    // ============ Roles ============
    bytes32 public constant ADMIN_ROLE   = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE  = keccak256("PAUSER_ROLE");
    bytes32 public constant TREASURER_ROLE = keccak256("TREASURER_ROLE");

    // ============ Types ============
    struct Permit2612 {
        uint256 value;    // allowance value for permit
        uint256 deadline; // signature deadline
        uint8   v;
        bytes32 r;
        bytes32 s;
    }

    struct ShieldParams {
        address asset;           // address(0) for ETH or ERC20 token address
        uint256 amount;          // amount to shield (not including fee)
        bytes32 commitment;      // ZK commitment identifier (unique)
        bytes   encryptedNote;   // ciphertext for client (opaque to contract)
        uint256 fee;             // protocol fee (charged upfront)
        address payer;           // who supplies funds (msg.sender if 0)
        bool    usePermit;       // if true, call ERC20 permit before transferFrom
        Permit2612 permit;       // EIP-2612 permit fields (ignored if usePermit=false or ETH)
    }

    struct UnshieldParams {
        address asset;           // address(0) for ETH or ERC20 token address
        uint256 amount;          // amount to withdraw
        address payable to;      // receiver
        bytes32 nullifier;       // unique nullifier preventing double-spend
        bytes   proof;           // opaque ZK proof verified by IVerifier
    }

    // ============ Events ============
    event Shielded(
        address indexed user,
        address indexed asset,
        uint256 amount,
        uint256 fee,
        bytes32 indexed commitment,
        bytes   encryptedNote
    );

    event Unshielded(
        address indexed caller,
        address indexed asset,
        uint256 amount,
        address indexed to,
        bytes32 nullifier
    );

    event VerifierUpdated(address oldVerifier, address newVerifier);
    event FeeRecipientUpdated(address oldRecipient, address newRecipient);
    event FeeBpsUpdated(uint16 oldBps, uint16 newBps);
    event AssetAllowlisted(address asset, bool allowed);

    // ============ Storage ============
    IVerifier public verifier;
    address public feeRecipient;
    uint16  public feeBps; // optional fallback fee (in basis points). 0 = off

    // asset => allowed
    mapping(address => bool) public isAssetAllowed;

    // commitment => stored (prevents accidental duplicates on client)
    mapping(bytes32 => bool) public commitmentUsed;

    // nullifier => spent
    mapping(bytes32 => bool) public nullifierSpent;

    // pooled balances per asset
    mapping(address => uint256) public poolBalance;

    // ETH marker
    address private constant NATIVE = address(0);

    // ============ Constructor ============
    constructor(address admin, address _verifier, address _feeRecipient, uint16 _feeBps) {
        require(admin != address(0), "admin=0");
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(TREASURER_ROLE, admin);

        verifier = IVerifier(_verifier);
        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
    }

    // ============ Admin ============
    function setVerifier(address v) external onlyRole(ADMIN_ROLE) {
        emit VerifierUpdated(address(verifier), v);
        verifier = IVerifier(v);
    }

    function setFeeRecipient(address r) external onlyRole(TREASURER_ROLE) {
        emit FeeRecipientUpdated(feeRecipient, r);
        feeRecipient = r;
    }

    function setFeeBps(uint16 bps) external onlyRole(TREASURER_ROLE) {
        require(bps <= 5000, "fee too high"); // <=50%
        emit FeeBpsUpdated(feeBps, bps);
        feeBps = bps;
    }

    function setAssetAllowed(address asset, bool allowed) external onlyRole(ADMIN_ROLE) {
        isAssetAllowed[asset] = allowed;
        emit AssetAllowlisted(asset, allowed);
    }

    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // ============ View helpers ============
    function previewFee(uint256 amount, uint256 providedFee) public view returns (uint256) {
        if (feeBps == 0) return providedFee;
        uint256 calc = (amount * uint256(feeBps)) / 10_000;
        return providedFee > 0 ? providedFee : calc;
    }

    function isNullifierSpent(bytes32 n) external view returns (bool) { return nullifierSpent[n]; }
    function isCommitmentUsed(bytes32 c) external view returns (bool) { return commitmentUsed[c]; }

    // ============ Core: Shield ============
    /// @notice Deposit ETH/ERC20 into the privacy pool and emit commitment.
    function shield(ShieldParams calldata p) external payable nonReentrant whenNotPaused {
        address asset = p.asset;
        require(isAssetAllowed[asset] || asset == NATIVE, "asset not allowed");
        require(!commitmentUsed[p.commitment], "commitment used");

        address payer = p.payer == address(0) ? msg.sender : p.payer;

        // Determine fee: if feeBps>0 and p.fee==0, compute; else use provided.
        uint256 fee = previewFee(p.amount, p.fee);
        uint256 total = p.amount + fee;

        if (asset == NATIVE) {
            require(msg.value == total, "bad msg.value");
            poolBalance[NATIVE] += p.amount;
            _transferETH(feeRecipient, fee);
        } else {
            IERC20 token = IERC20(asset);

            if (p.usePermit) {
                // Best-effort permit; if token doesn't implement permit this will revert
                IERC20Permit(asset).permit(
                    payer, address(this), p.permit.value, p.permit.deadline, p.permit.v, p.permit.r, p.permit.s
                );
            }

            uint256 beforeBal = token.balanceOf(address(this));
            token.safeTransferFrom(payer, address(this), total);
            uint256 received = token.balanceOf(address(this)) - beforeBal;
            require(received >= total, "deflationary token");
            poolBalance[asset] += p.amount;
            if (fee > 0) {
                token.safeTransfer(feeRecipient, fee);
            }
        }

        commitmentUsed[p.commitment] = true;
        emit Shielded(payer, asset, p.amount, fee, p.commitment, p.encryptedNote);
    }

    // ============ Core: Unshield ============
    /// @notice Withdraw from the privacy pool after ZK verification; prevents double spend via nullifier.
    function unshield(UnshieldParams calldata p) external nonReentrant whenNotPaused {
        require(!nullifierSpent[p.nullifier], "nullifier spent");
        require(isAssetAllowed[p.asset] || p.asset == NATIVE, "asset not allowed");
        require(p.amount > 0, "amount=0");

        // Verify ZK proof via external verifier
        require(
            verifier.verifyUnshield(p.proof, p.nullifier, p.asset, p.amount, p.to),
            "invalid proof"
        );

        nullifierSpent[p.nullifier] = true;

        if (p.asset == NATIVE) {
            require(poolBalance[NATIVE] >= p.amount, "insufficient pool");
            poolBalance[NATIVE] -= p.amount;
            _transferETH(p.to, p.amount);
        } else {
            IERC20 token = IERC20(p.asset);
            require(poolBalance[p.asset] >= p.amount, "insufficient pool");
            poolBalance[p.asset] -= p.amount;
            token.safeTransfer(p.to, p.amount);
        }

        emit Unshielded(msg.sender, p.asset, p.amount, p.to, p.nullifier);
    }

    // ============ Rescue (admin) ============
    /// @notice Emergency sweep of mistakenly sent tokens (not part of pool). Only admin.
    function rescueERC20(address token, address to, uint256 amount) external onlyRole(ADMIN_ROLE) {
        IERC20(token).safeTransfer(to, amount);
    }

    /// @notice Emergency sweep of ETH (not part of pool). Only admin.
    function rescueETH(address payable to, uint256 amount) external onlyRole(ADMIN_ROLE) {
        _transferETH(to, amount);
    }

    // ============ Internal ============
    function _transferETH(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "eth transfer failed");
    }

    receive() external payable {}
    fallback() external payable {}
}

/* ========= Verifier Interface ========= */

interface IVerifier {
    /// @notice Verify unshield proof and binding public inputs.
    /// @dev MUST return true only if proof is valid and bound to (nullifier, asset, amount, to).
    function verifyUnshield(
        bytes calldata proof,
        bytes32 nullifier,
        address asset,
        uint256 amount,
        address to
    ) external view returns (bool);
}

/* ========= Minimal ERC20/Permit Interfaces & Safe wrappers ========= */

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256) external returns (bool);
    function transfer(address to, uint256) external returns (bool);
    function transferFrom(address from, address to, uint256) external returns (bool);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "ERC20 call failed");
        if (returndata.length > 0) {
            require(abi.decode(returndata, (bool)), "ERC20 op failed");
        }
    }
}

/* ========= Lightweight Roles, Pause, Reentrancy ========= */

abstract contract AccessControlLite {
    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "missing role");
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }
}

abstract contract PausableLite {
    bool private _paused;
    event Paused(address account);
    event Unpaused(address account);

    modifier whenNotPaused() {
        require(!_paused, "paused");
        _;
    }

    function paused() public view returns (bool) { return _paused; }

    function _pause() internal {
        require(!_paused, "already paused");
        _paused = true;
        emit Paused(msg.sender);
    }

    function _unpause() internal {
        require(_paused, "not paused");
        _paused = false;
        emit Unpaused(msg.sender);
    }
}

abstract contract ReentrancyGuardLite {
    uint256 private constant _ENTERED = 2;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "reentrancy");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}
