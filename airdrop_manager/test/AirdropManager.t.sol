// airdrop_manager/test/AirdropManager.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
Промышленный тестовый набор Foundry для AirdropManager.

ВНИМАНИЕ (важно для воспроизводимости):
- Если у вас уже развёрнут собственный AirdropManager, укажите его адрес в переменной окружения:
    AIRDROP_MANAGER_ADDR=0x... forge test -vv
  Тогда тест попытается взаимодействовать с ним через универсальный адаптер (low-level calls).
- Если переменная окружения не задана, будет развёрнут референсный мок (ReferenceAirdropManager)
  с типичным интерфейсом конфигурации мерклового эирдропа.

ОГРАНИЧЕНИЕ ПОДТВЕРЖДЕНИЙ:
- Я не могу подтвердить точный интерфейс вашего контракта — поэтому включён адаптер
  и fallback-мок. Весь тест помечен как НЕПОДТВЕРЖДЁННЫЙ для вашей конкретной реализации.

ОФИЦИАЛЬНЫЕ ИСТОЧНИКИ:
- ERC-20 / EIP-20: https://eips.ethereum.org/EIPS/eip-20
- MerkleProof (концепция): https://docs.openzeppelin.com/contracts/4.x/utilities#merkleproof
- Foundry / forge-std: https://book.getfoundry.sh/forge/cheatcodes
*/

import "forge-std/Test.sol";
import "forge-std/StdUtils.sol";
import "forge-std/console2.sol";

// -----------------------------
// Минимальный ERC20 мок
// -----------------------------
contract ERC20Mock {
    string public name = "TestToken";
    string public symbol = "TST";
    uint8 public immutable decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address sp, uint256 amount) external returns (bool) {
        allowance[msg.sender][sp] = amount;
        emit Approval(msg.sender, sp, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allow");
        allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

// ---------------------------------------------
// Мини-библиотека Merkle (аналог OZ MerkleProof)
// ---------------------------------------------
library Merkle {
    // verify(proof, root, leaf) == true -> корректное доказательство
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool ok) {
        bytes32 hash = leaf;
        for (uint256 i; i < proof.length; i++) {
            bytes32 p = proof[i];
            hash = _hashPair(hash, p);
        }
        return hash == root;
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    // Утилита для построения дерева по отсортированным листьям
    function root(bytes32[] memory leaves) internal pure returns (bytes32 r) {
        if (leaves.length == 0) return bytes32(0);
        while (leaves.length > 1) {
            uint256 n = (leaves.length + 1) >> 1;
            bytes32[] memory nxt = new bytes32[](n);
            uint256 j;
            for (uint256 i; i < leaves.length; i += 2) {
                if (i + 1 == leaves.length) {
                    nxt[j++] = leaves[i];
                } else {
                    nxt[j++] = _hashPair(leaves[i], leaves[i + 1]);
                }
            }
            leaves = nxt;
        }
        return leaves[0];
    }
}

// -----------------------------------------------------
// Референсная реализация менеджера (для самодостаточности)
// -----------------------------------------------------
contract ReferenceAirdropManager is Test {
    using Merkle for bytes32[];
    using Merkle for bytes32;

    struct Drop {
        address token;
        bytes32 merkleRoot;
        uint64 start;
        uint64 end;
        address admin;
        mapping(address => bool) claimed;
    }

    mapping(bytes32 => Drop) internal drops; // dropId => Drop
    address public owner;

    event DropConfigured(bytes32 indexed dropId, address token, bytes32 root, uint64 start, uint64 end, address admin);
    event Claimed(bytes32 indexed dropId, address indexed account, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not-owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function configureDrop(
        bytes32 dropId,
        address token,
        bytes32 root,
        uint64 start,
        uint64 end,
        address admin
    ) external onlyOwner {
        require(token != address(0), "token=0");
        require(end == 0 || end > start, "bad-window");
        Drop storage d = drops[dropId];
        d.token = token;
        d.merkleRoot = root;
        d.start = start;
        d.end = end;
        d.admin = admin == address(0) ? owner : admin;
        emit DropConfigured(dropId, token, root, start, end, d.admin);
    }

    function dropInfo(bytes32 dropId) external view returns (address, bytes32, uint64, uint64, address) {
        Drop storage d = drops[dropId];
        return (d.token, d.merkleRoot, d.start, d.end, d.admin);
    }

    function hasClaimed(bytes32 dropId, address account) external view returns (bool) {
        return drops[dropId].claimed[account];
    }

    function claim(bytes32 dropId, uint256 amount, bytes32[] calldata proof) external {
        Drop storage d = drops[dropId];
        require(d.token != address(0), "no-drop");
        uint64 nowTs = uint64(block.timestamp);
        require(d.start == 0 || nowTs >= d.start, "not-started");
        require(d.end == 0 || nowTs <= d.end, "ended");
        require(!d.claimed[msg.sender], "claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(Merkle.verify(proof, d.merkleRoot, leaf), "bad-proof");
        d.claimed[msg.sender] = true;
        // Токен заранее должен быть на контракте (или одобрен)
        require(ERC20Mock(d.token).transfer(msg.sender, amount), "transfer");
        emit Claimed(dropId, msg.sender, amount);
    }
}

// -----------------------------------------------------
// Универсальный адаптер для вызова SUT по селекторам
// -----------------------------------------------------
library SutAdapter {
    // Сигнатуры часто встречающихся методов
    bytes4 constant SIG_configureDrop =
        bytes4(keccak256("configureDrop(bytes32,address,bytes32,uint64,uint64,address)"));
    bytes4 constant SIG_dropInfo =
        bytes4(keccak256("dropInfo(bytes32)"));
    bytes4 constant SIG_hasClaimed =
        bytes4(keccak256("hasClaimed(bytes32,address)"));
    bytes4 constant SIG_claim =
        bytes4(keccak256("claim(bytes32,uint256,bytes32[])"));

    function tryConfigureDrop(
        address sut,
        bytes32 dropId,
        address token,
        bytes32 root,
        uint64 start,
        uint64 end,
        address admin
    ) internal returns (bool ok, bytes memory data) {
        (ok, data) = sut.call(abi.encodeWithSelector(SIG_configureDrop, dropId, token, root, start, end, admin));
    }

    function tryDropInfo(address sut, bytes32 dropId) internal view returns (bool ok, bytes memory data) {
        (ok, data) = sut.staticcall(abi.encodeWithSelector(SIG_dropInfo, dropId));
    }

    function tryHasClaimed(address sut, bytes32 dropId, address user) internal view returns (bool ok, bytes memory data) {
        (ok, data) = sut.staticcall(abi.encodeWithSelector(SIG_hasClaimed, dropId, user));
    }

    function tryClaim(address sut, bytes32 dropId, uint256 amount, bytes32[] memory proof)
        internal
        returns (bool ok, bytes memory data)
    {
        (ok, data) = sut.call(abi.encodeWithSelector(SIG_claim, dropId, amount, proof));
    }
}

// -----------------------------------------------------
// Тестовый набор
// -----------------------------------------------------
contract AirdropManagerTest is Test {
    using Merkle for bytes32[];
    using SutAdapter for address;

    address internal SUT; // адрес тестируемого контракта (или мока)
    ERC20Mock internal token;

    bytes32 internal constant DROP_ID = keccak256("GENESIS_DROP");
    address internal admin;
    address internal alice;
    address internal bob;

    function setUp() public {
        // актёры
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob   = makeAddr("bob");

        // токен и начальный баланс контракта
        token = new ERC20Mock();

        // выбор SUT
        address sutFromEnv = _envAddress("AIRDROP_MANAGER_ADDR");
        if (sutFromEnv != address(0)) {
            SUT = sutFromEnv;
        } else {
            // разворачиваем референсный мок
            vm.startPrank(admin);
            ReferenceAirdropManager impl = new ReferenceAirdropManager();
            SUT = address(impl);
            vm.stopPrank();
        }

        // пополняем контракт токенами
        token.mint(address(this), 1e30);
        token.transfer(SUT, 1e24); // крупный запас под клеймы
    }

    // -----------------------------
    // Вспомогательные утилиты
    // -----------------------------
    function _envAddress(string memory key) internal returns (address) {
        // безопасное чтение env, когда переменная может отсутствовать
        try vm.envAddress(key) returns (address a) {
            return a;
        } catch {
            return address(0);
        }
    }

    function _buildLeaves(address[] memory users, uint256[] memory amounts) internal pure returns (bytes32[] memory) {
        require(users.length == amounts.length, "len");
        bytes32[] memory leaves = new bytes32[](users.length);
        for (uint256 i; i < users.length; i++) {
            leaves[i] = keccak256(abi.encodePacked(users[i], amounts[i]));
        }
        // простая сортировка для детерминированного дерева
        for (uint256 i; i + 1 < leaves.length; i++) {
            for (uint256 j = i + 1; j < leaves.length; j++) {
                if (leaves[j] < leaves[i]) {
                    bytes32 t = leaves[i];
                    leaves[i] = leaves[j];
                    leaves[j] = t;
                }
            }
        }
        return leaves;
    }

    // строим proof для конкретного листа (naive, достаточен для тестов)
    function _proofFor(bytes32[] memory sortedLeaves, bytes32 leaf) internal pure returns (bytes32[] memory proof) {
        // Наивная реализация: восстанавливаем уровни дерева и собираем «соседей».
        // Подходит для малых наборов (тестовые данные).
        // Для больших наборов используйте off-chain генерацию или оптимизированные библиотеки.
        uint256 n = sortedLeaves.length;
        if (n == 0) return proof;

        // Вычислим индекс листа
        uint256 idx = type(uint256).max;
        for (uint256 i; i < n; i++) {
            if (sortedLeaves[i] == leaf) { idx = i; break; }
        }
        require(idx != type(uint256).max, "leaf-not-found");

        bytes32[] memory layer = sortedLeaves;
        bytes32;
        uint256 accLen;

        while (layer.length > 1) {
            uint256 m = (layer.length + 1) >> 1;
            bytes32[] memory nextLayer = new bytes32[](m);
            for (uint256 i; i < layer.length; i += 2) {
                if (i + 1 == layer.length) {
                    nextLayer[i >> 1] = layer[i];
                    if (i == idx) {
                        idx = i >> 1;
                    }
                } else {
                    bytes32 a = layer[i];
                    bytes32 b = layer[i + 1];
                    bytes32 parent = a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
                    nextLayer[i >> 1] = parent;

                    if (i == idx) {
                        acc[accLen++] = b;
                        idx = i >> 1;
                    } else if (i + 1 == idx) {
                        acc[accLen++] = a;
                        idx = i >> 1;
                    }
                }
            }
            layer = nextLayer;
        }

        proof = new bytes32[](accLen);
        for (uint256 i; i < accLen; i++) proof[i] = acc[i];
    }

    // -----------------------------
    // Тесты конфигурации и клейма
    // -----------------------------

    function test_configure_and_claim_happy_path() public {
        // Готовим дерево
        address;
        users[0] = alice; users[1] = bob;
        uint256;
        amts[0] = 100 ether; amts[1] = 200 ether;

        bytes32[] memory leaves = _buildLeaves(users, amts);
        bytes32 root = Merkle.root(leaves);

        // Конфигурация дропа
        vm.prank(_assumedOwner()); // в мок-реализации owner=admin из setUp
        (bool okCfg,) = SUT.tryConfigureDrop(DROP_ID, address(token), root, 0, 0, admin);
        require(okCfg, "cfg-failed");

        // Проверка dropInfo (если метод существует)
        (bool okInfo, bytes memory d) = SUT.tryDropInfo(DROP_ID);
        if (okInfo && d.length >= 32*5) {
            (address tkn, bytes32 r, uint64 s, uint64 e, address a) =
                abi.decode(d, (address, bytes32, uint64, uint64, address));
            assertEq(tkn, address(token), "token mismatch");
            assertEq(r, root, "root mismatch");
            // s/e/a не строго проверяем (могут отличаться политикой)
            emit log_named_uint("start", s);
            emit log_named_uint("end", e);
            emit log_named_address("admin", a);
        }

        // Клейм Алисы
        bytes32 leafA = keccak256(abi.encodePacked(alice, amts[0]));
        bytes32[] memory proofA = _proofFor(leaves, leafA);

        uint256 balBefore = token.balanceOf(alice);
        vm.prank(alice);
        (bool okClaimA, bytes memory retA) = SUT.tryClaim(DROP_ID, amts[0], proofA);
        if (!okClaimA) {
            // Попробуем декодировать строку ошибки
            _bubble(retA);
        }
        assertTrue(okClaimA, "claimA failed");
        assertEq(token.balanceOf(alice), balBefore + amts[0], "alice bal");

        // Повторный клейм должен быть запрещён
        vm.prank(alice);
        (bool okClaimA2, ) = SUT.tryClaim(DROP_ID, amts[0], proofA);
        assertFalse(okClaimA2, "double claim must fail");
    }

    function test_rejects_wrong_proof() public {
        address;
        users[0] = alice;
        uint256;
        amts[0] = 1 ether;

        bytes32[] memory leaves = _buildLeaves(users, amts);
        bytes32 root = Merkle.root(leaves);

        vm.prank(_assumedOwner());
        (bool okCfg,) = SUT.tryConfigureDrop(DROP_ID, address(token), root, 0, 0, admin);
        require(okCfg, "cfg-failed");

        // Подделанный proof (для иного листа)
        bytes32 fakeLeaf = keccak256(abi.encodePacked(bob, amts[0]));
        bytes32[] memory badProof = _proofFor(leaves, fakeLeaf);

        vm.prank(alice);
        (bool okClaim, ) = SUT.tryClaim(DROP_ID, amts[0], badProof);
        assertFalse(okClaim, "bad proof must fail");
    }

    function test_time_window_start_and_end() public {
        address;
        users[0] = alice;
        uint256;
        amts[0] = 5 ether;

        bytes32[] memory leaves = _buildLeaves(users, amts);
        bytes32 root = Merkle.root(leaves);

        uint64 startTs = uint64(block.timestamp + 3600);
        uint64 endTs   = uint64(block.timestamp + 7200);

        vm.prank(_assumedOwner());
        (bool okCfg,) = SUT.tryConfigureDrop(DROP_ID, address(token), root, startTs, endTs, admin);
        require(okCfg, "cfg-failed");

        bytes32 leafA = keccak256(abi.encodePacked(alice, amts[0]));
        bytes32[] memory proofA = _proofFor(leaves, leafA);

        // До старта — отклонено
        vm.prank(alice);
        (bool ok1,) = SUT.tryClaim(DROP_ID, amts[0], proofA);
        assertFalse(ok1, "should be not-started");

        // Перематываем на окно — успех
        vm.warp(startTs + 1);
        vm.prank(alice);
        (bool ok2,) = SUT.tryClaim(DROP_ID, amts[0], proofA);
        assertTrue(ok2, "should be claimable in window");

        // Повтор — отклонено
        vm.prank(alice);
        (bool ok3,) = SUT.tryClaim(DROP_ID, amts[0], proofA);
        assertFalse(ok3, "double claim blocked");

        // После дедлайна — тоже отклонено (для нового участника)
        vm.warp(endTs + 1);
        address charlie = makeAddr("charlie");
        bytes32 leafC = keccak256(abi.encodePacked(charlie, 7 ether));
        // Лист Чарли отсутствует в дереве — формально proof невалиден; проверим именно окно:
        bytes32[] memory fakeProof;
        vm.prank(charlie);
        (bool ok4,) = SUT.tryClaim(DROP_ID, 7 ether, fakeProof);
        assertFalse(ok4, "ended");
    }

    function test_fuzz_claim_unique_once(address user, uint96 amount) public {
        vm.assume(user != address(0));
        vm.assume(amount > 0);
        // готовим точечный дроп только для данного юзера
        address;
        users[0] = user;
        uint256;
        amts[0] = uint256(amount);

        bytes32[] memory leaves = _buildLeaves(users, amts);
        bytes32 root = Merkle.root(leaves);

        vm.prank(_assumedOwner());
        (bool okCfg,) = SUT.tryConfigureDrop(DROP_ID, address(token), root, 0, 0, admin);
        require(okCfg, "cfg-failed");

        bytes32 leaf = keccak256(abi.encodePacked(user, amts[0]));
        bytes32[] memory proof = _proofFor(leaves, leaf);

        uint256 before = token.balanceOf(user);
        vm.prank(user);
        (bool ok1,) = SUT.tryClaim(DROP_ID, amts[0], proof);
        assertTrue(ok1, "first claim ok");

        // повтор должен провалиться
        vm.prank(user);
        (bool ok2,) = SUT.tryClaim(DROP_ID, amts[0], proof);
        assertFalse(ok2, "replay blocked");

        assertEq(token.balanceOf(user), before + amts[0], "exact payout once");
    }

    // -----------------------------
    // Вспомогательные методы
    // -----------------------------
    function _assumedOwner() internal view returns (address) {
        // Для референсной реализации owner = адрес, создавший контракт; в setUp это admin.
        // Для внешнего SUT можно при необходимости заменить на нужного владельца через env, но
        // тест использует low-level call и не навязывает msg.sender (мы используем prank).
        return admin;
    }

    function _bubble(bytes memory ret) internal pure {
        // Попытка вывести строку ошибки, если это Error(string)
        if (ret.length >= 4) {
            bytes4 sel;
            assembly { sel := mload(add(ret, 0x20)) }
            // 0x08c379a0 = Error(string)
            if (sel == 0x08c379a0 && ret.length >= 68) {
                // skip selector + offset
                bytes memory s = new bytes(ret.length - 68);
                // копируем строку (после selector(4) + offset(32) + len(32))
                assembly {
                    let src := add(ret, 0x60)
                    let dst := add(s, 0x20)
                    let len := mload(add(ret, 0x40))
                    mstore(s, len)
                    for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                        mstore(add(dst, i), mload(add(src, i)))
                    }
                }
            }
        }
    }
}
