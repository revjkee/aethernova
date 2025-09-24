// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
  Foundry test helpers for airdrop flows:
  - Users & keys factory (deterministic makeAddrAndKey-like)
  - ERC20 permit (EIP-2612) signing helpers (EIP-712)
  - Merkle tree + proof generation (sorted pairs)
  - Deal/mint/approve helpers
  - Address/uint bounding and labeling
  - Minimal MockERC20Permit for integration tests

  Dependencies assumed:
    forge-std >= 1.9.0
*/

import "forge-std/Test.sol";

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address who, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

interface IERC20Permit {
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
}

contract MockERC20Permit is IERC20, IERC20Permit {
    string public name;
    string public symbol;
    uint8 public immutable decimals = 18;

    mapping(address => uint256) private _bal;
    mapping(address => mapping(address => uint256)) private _allow;
    uint256 private _supply;

    // EIP-2612
    mapping(address => uint256) public override nonces;
    bytes32 public immutable override DOMAIN_SEPARATOR;
    bytes32 private constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant _EIP712DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(_name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // --- ERC20 core ---
    function totalSupply() external view override returns (uint256) { return _supply; }
    function balanceOf(address who) public view override returns (uint256) { return _bal[who]; }
    function allowance(address who, address spender) external view override returns (uint256) { return _allow[who][spender]; }

    function approve(address spender, uint256 value) public override returns (bool) {
        _allow[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        uint256 a = _allow[from][msg.sender];
        require(a >= value, "ALLOW");
        unchecked { _allow[from][msg.sender] = a - value; }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "ZERO_TO");
        uint256 b = _bal[from];
        require(b >= value, "BAL");
        unchecked { _bal[from] = b - value; }
        _bal[to] += value;
        emit Transfer(from, to, value);
    }

    // --- Mint for tests ---
    function mint(address to, uint256 amount) external {
        require(to != address(0), "ZERO_TO");
        _supply += amount;
        _bal[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    // --- EIP-2612 permit ---
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external override {
        require(block.timestamp <= deadline, "DEADLINE");
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(_PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
            )
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "SIG");
        _allow[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    // --- Events ---
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

/// @notice Common helpers mixin for airdrop tests
contract Helpers is Test {
    // =========================
    // Constants & typehashes
    // =========================
    bytes32 internal constant _EIP712DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // =========================
    // User & key utilities
    // =========================

    /// @notice Create N labeled users with deterministic private keys
    function createUsers(uint256 n, string memory labelPrefix) public returns (address[] memory users, uint256[] memory keys) {
        users = new address[](n);
        keys = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            (address a, uint256 pk) = _makeAddrAndKey(string.concat(labelPrefix, "_", vm.toString(i)));
            users[i] = a;
            keys[i] = pk;
            vm.label(a, string.concat(labelPrefix, "#", vm.toString(i)));
            vm.deal(a, 100 ether);
        }
    }

    /// @notice Single user factory (compat with forge-std's makeAddrAndKey)
    function _makeAddrAndKey(string memory name_) internal returns (address a, uint256 pk) {
        // forge-std provides makeAddrAndKey; we replicate deterministically here for portability
        bytes32 sk = keccak256(abi.encodePacked("aethernova/helpers:", name_));
        pk = uint256(sk);
        a = vm.addr(pk);
    }

    // =========================
    // ERC20 helpers
    // =========================

    /// @notice Mint on MockERC20Permit and approve spender
    function mintAndApprove(MockERC20Permit token, address to, address spender, uint256 amount) public {
        token.mint(to, amount);
        vm.startPrank(to);
        token.approve(spender, amount);
        vm.stopPrank();
        assertEq(token.balanceOf(to), amount, "minted balance mismatch");
        assertEq(token.allowance(to, spender), amount, "allowance mismatch");
    }

    /// @notice Set ERC20 balance via cheatcode (fallbacks to mint for MockERC20Permit)
    function dealERC20(address token, address to, uint256 amount) public {
        // StdCheats.deal works for many ERC20s; for our mock we can mint directly
        try MockERC20Permit(token).mint(to, amount) {
            // ok
        } catch {
            deal(token, to, amount, true);
        }
        assertEq(IERC20(token).balanceOf(to), amount, "dealERC20 failed");
    }

    // =========================
    // Permit (EIP-2612) helpers
    // =========================

    /// @notice Compute EIP-712 domain separator for arbitrary ERC20(permit)
    function computeDomainSeparator(
        string memory name_,
        string memory version_,
        uint256 chainId_,
        address verifying
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(name_)),
                keccak256(bytes(version_)),
                chainId_,
                verifying
            )
        );
    }

    /// @notice Compute digest for EIP-2612 permit
    function computePermitDigest(
        bytes32 domainSeparator,
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(_PERMIT_TYPEHASH, owner, spender, value, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @notice Sign permit for arbitrary token using private key
    function signPermit(
        uint256 pk,
        bytes32 domainSeparator,
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = computePermitDigest(domainSeparator, owner, spender, value, nonce, deadline);
        (v, r, s) = vm.sign(pk, digest);
    }

    /// @notice Convenience: sign+submit permit to token
    function submitPermit(
        IERC20Permit token,
        uint256 pk,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline
    ) public {
        bytes32 ds = token.DOMAIN_SEPARATOR();
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = signPermit(pk, ds, owner, spender, value, nonce, deadline);
        token.permit(owner, spender, value, deadline, v, r, s);
    }

    // =========================
    // Merkle tree helpers (sorted pairs)
    // =========================

    /// @notice Build Merkle root from leaves; leaves are already hashed (bytes32)
    function merkleRoot(bytes32[] memory leaves) public pure returns (bytes32) {
        uint256 n = leaves.length;
        if (n == 0) return bytes32(0);
        while (n > 1) {
            uint256 k = 0;
            for (uint256 i = 0; i < n; i += 2) {
                if (i + 1 == n) {
                    leaves[k++] = leaves[i];
                } else {
                    leaves[k++] = _hashPair(leaves[i], leaves[i + 1]);
                }
            }
            n = k;
        }
        return leaves[0];
    }

    /// @notice Generate Merkle proof for leaf at index (sorted pairs)
    function merkleProof(bytes32[] memory leaves, uint256 index) public pure returns (bytes32[] memory proof) {
        require(leaves.length > 0 && index < leaves.length, "bad index");
        uint256 n = leaves.length;
        uint256 idx = index;
        uint256 depth = _treeDepth(n);
        proof = new bytes32[](depth);
        uint256 p = 0;

        while (n > 1) {
            if (idx % 2 == 0) {
                // right sibling or carry
                if (idx + 1 < n) {
                    proof[p++] = leaves[idx + 1];
                } else {
                    proof[p++] = bytes32(0); // placeholder (ignored by typical verifiers)
                }
            } else {
                proof[p++] = leaves[idx - 1];
            }

            // fold layer
            uint256 k = 0;
            for (uint256 i = 0; i < n; i += 2) {
                if (i + 1 == n) {
                    leaves[k++] = leaves[i];
                } else {
                    leaves[k++] = _hashPair(leaves[i], leaves[i + 1]);
                }
            }
            n = k;
            idx /= 2;
        }

        // trim trailing zero placeholders
        uint256 m = proof.length;
        while (m > 0 && proof[m - 1] == bytes32(0)) m--;
        assembly { mstore(proof, m) }
    }

    function _treeDepth(uint256 n) internal pure returns (uint256 d) {
        while (n > 1) { n = (n + 1) / 2; d++; }
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return (a < b) ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    // =========================
    // General assertions & utils
    // =========================

    function label(address a, string memory what) public {
        vm.label(a, what);
    }

    function boundAddress(address a) public pure returns (address) {
        // no-op here; kept for API symmetry
        return a;
    }

    function boundUint(uint256 x, uint256 minVal, uint256 maxVal) public pure returns (uint256) {
        return x % (maxVal - minVal + 1) + minVal;
    }

    function toBytes32(address a) public pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    // =========================
    // Scenario bootstrap helpers
    // =========================

    /// @notice Deploys a fresh MockERC20Permit with given name/symbol
    function deployMockToken(string memory name_, string memory symbol_) public returns (MockERC20Permit tkn) {
        tkn = new MockERC20Permit(name_, symbol_);
        vm.label(address(tkn), string.concat("MockERC20Permit:", name_));
    }

    /// @notice Funds user with ETH and ERC20 and prepares allowance
    function fundUser(
        address user,
        MockERC20Permit token,
        uint256 ethAmount,
        uint256 ercAmount,
        address spender
    ) public {
        vm.deal(user, ethAmount);
        token.mint(user, ercAmount);
        vm.startPrank(user);
        token.approve(spender, ercAmount);
        vm.stopPrank();
        assertEq(token.balanceOf(user), ercAmount, "fundUser: ERC20 bal");
        assertEq(token.allowance(user, spender), ercAmount, "fundUser: allowance");
    }
}
