// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Foundry standard library for testing
import "forge-std/Test.sol";

// Предполагаемый путь до контракта дистрибутора в вашем репозитории.
// Если у вас другой путь/имя — обновите импорт.
import {MerkleDistributor} from "../src/MerkleDistributor.sol";

/// @notice Минимальный ERC20 для тестов с чеканкой (без внешних зависимостей)
contract MockERC20 {
    string public name = "MockToken";
    string public symbol = "MOCK";
    uint8 public immutable decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        return _transfer(msg.sender, to, value);
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "ERC20: insufficient allowance");
            allowance[from][msg.sender] = allowed - value;
        }
        return _transfer(from, to, value);
    }

    function _transfer(address from, address to, uint256 value) internal returns (bool) {
        require(balanceOf[from] >= value, "ERC20: insufficient balance");
        unchecked {
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
        return true;
    }
}

/// @notice Вспомогательная библиотека для построения Merkle-дерева/пруфов
library TestMerkle {
    /// @dev Хэш листа по схеме Uniswap: keccak256(abi.encodePacked(index, account, amount))
    function leaf(uint256 index, address account, uint256 amount) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(index, account, amount));
    }

    /// @dev Коммутативное хеширование пары (сортировка по значению), как ожидает OpenZeppelin MerkleProof
    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /// @dev Строит корень из массива листьев (длина должна быть степенью 2)
    function root(bytes32[] memory leaves) internal pure returns (bytes32 r) {
        require(leaves.length > 0 && (leaves.length & (leaves.length - 1)) == 0, "len must be power of 2");
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            uint256 n = level.length / 2;
            bytes32[] memory next = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                next[i] = _hashPair(level[2 * i], level[2 * i + 1]);
            }
            level = next;
        }
        return level[0];
    }

    /// @dev Возвращает Merkle-пруф для leaves[index]. leaves.length — степень 2
    function proof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory) {
        require(leaves.length > 0 && (leaves.length & (leaves.length - 1)) == 0, "len must be power of 2");
        bytes32[] memory level = leaves;
        bytes32[] memory path = new bytes32[](log2(leaves.length));
        uint256 pos = 0;
        uint256 idx = index;

        while (level.length > 1) {
            uint256 n = level.length / 2;
            bytes32[] memory next = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                bytes32 L = level[2 * i];
                bytes32 R = level[2 * i + 1];
                next[i] = _hashPair(L, R);
            }
            // добавить соседа на текущем уровне
            uint256 sibling = idx ^ 1;
            path[pos++] = level[sibling];

            level = next;
            idx /= 2;
        }
        return path;
    }

    function log2(uint256 x) private pure returns (uint256 y) {
        while (x > 1) {
            x >>= 1;
            y++;
        }
    }
}

/// @notice Тесты для MerkleDistributor
contract MerkleDistributorTest is Test {
    // Тестовые адреса
    address internal alice = address(0xA11CE);
    address internal bob   = address(0xB0B);
    address internal carol = address(0xCAFE);
    address internal dan   = address(0xD00D);

    MockERC20 internal token;
    MerkleDistributor internal distributor;

    // Данные airdrop
    uint256 internal amountAlice = 100 ether;
    uint256 internal amountBob   = 200 ether;
    uint256 internal amountCarol = 300 ether;
    uint256 internal amountDan   = 400 ether;

    bytes32[] internal leaves; // индекс совпадает с index в дереве
    bytes32 internal merkleRoot;

    function setUp() public {
        vm.label(alice, "ALICE");
        vm.label(bob,   "BOB");
        vm.label(carol, "CAROL");
        vm.label(dan,   "DAN");

        token = new MockERC20();

        // 4 листа (степень 2) для детерминированного дерева
        leaves = new bytes32;
        leaves[0] = TestMerkle.leaf(0, alice, amountAlice);
        leaves[1] = TestMerkle.leaf(1, bob,   amountBob);
        leaves[2] = TestMerkle.leaf(2, carol, amountCarol);
        leaves[3] = TestMerkle.leaf(3, dan,   amountDan);

        merkleRoot = TestMerkle.root(leaves);

        // Развернуть дистрибьютор по интерфейсу Uniswap-стиля: (token, merkleRoot)
        // ВАЖНО: если у вас иная сигнатура конструктора — адаптируйте строку ниже.
        distributor = new MerkleDistributor(address(token), merkleRoot);

        // Фондируем дистрибьютор токенами на полную сумму
        token.mint(address(distributor), amountAlice + amountBob + amountCarol + amountDan);
    }

    function test_Claim_Success() public {
        // Готовим пруф для Alice (index=0)
        bytes32[] memory proofAlice = TestMerkle.proof(leaves, 0);
        uint256 beforeBalance = token.balanceOf(alice);

        // Клаймим от имени любого инициатора — в классическом Uniswap-варианте
        // перевод идет на account из листа (alice).
        distributor.claim(0, alice, amountAlice, proofAlice);

        assertEq(token.balanceOf(alice), beforeBalance + amountAlice, "wrong alice balance after claim");
        assertTrue(distributor.isClaimed(0), "index 0 should be marked claimed");
    }

    function test_Revert_InvalidProof() public {
        // Пруф Bob пробуем применить к Alice — должен ревертиться
        bytes32[] memory proofBob = TestMerkle.proof(leaves, 1);
        vm.expectRevert(); // конкретная строка/селектор зависят от реализации
        distributor.claim(0, alice, amountAlice, proofBob);
    }

    function test_Revert_ClaimTwice() public {
        bytes32[] memory proofCarol = TestMerkle.proof(leaves, 2);
        distributor.claim(2, carol, amountCarol, proofCarol);

        // Повторный клайм того же индекса — реверт
        vm.expectRevert();
        distributor.claim(2, carol, amountCarol, proofCarol);
    }

    function test_Revert_InsufficientDistributorBalance() public {
        // Создаем новый дистрибьютор без достаточного баланса
        MerkleDistributor poor = new MerkleDistributor(address(token), merkleRoot);
        // Фондируем заведомо меньшей суммой
        token.mint(address(poor), 10 ether);

        bytes32[] memory proofDan = TestMerkle.proof(leaves, 3);

        vm.expectRevert(); // transfer в токене провалится по недостатку средств poor
        poor.claim(3, dan, amountDan, proofDan);
    }

    function testFuzz_Revert_AlteredAmount(uint96 delta) public {
        vm.assume(delta != 0);
        bytes32[] memory proofBob = TestMerkle.proof(leaves, 1);

        // Подменяем amount на неверный
        uint256 wrongAmount = amountBob + uint256(delta);
        vm.expectRevert();
        distributor.claim(1, bob, wrongAmount, proofBob);
    }

    function testFuzz_Revert_AlteredIndex(uint8 wrongIndex) public {
        vm.assume(wrongIndex != 0 && wrongIndex < 128); // просто чтобы не совпало с 0
        bytes32[] memory proofAlice = TestMerkle.proof(leaves, 0);
        vm.expectRevert();
        distributor.claim(uint256(wrongIndex), alice, amountAlice, proofAlice);
    }

    function test_SumsMatchAfterAllClaims() public {
        bytes32[] memory p0 = TestMerkle.proof(leaves, 0);
        bytes32[] memory p1 = TestMerkle.proof(leaves, 1);
        bytes32[] memory p2 = TestMerkle.proof(leaves, 2);
        bytes32[] memory p3 = TestMerkle.proof(leaves, 3);

        distributor.claim(0, alice, amountAlice, p0);
        distributor.claim(1, bob,   amountBob,   p1);
        distributor.claim(2, carol, amountCarol, p2);
        distributor.claim(3, dan,   amountDan,   p3);

        uint256 total = amountAlice + amountBob + amountCarol + amountDan;
        assertEq(token.balanceOf(address(distributor)), 0, "residual balance");
        assertEq(
            token.balanceOf(alice) + token.balanceOf(bob) + token.balanceOf(carol) + token.balanceOf(dan),
            total,
            "sum of recipients must equal total"
        );
        assertTrue(distributor.isClaimed(0));
        assertTrue(distributor.isClaimed(1));
        assertTrue(distributor.isClaimed(2));
        assertTrue(distributor.isClaimed(3));
    }
}
