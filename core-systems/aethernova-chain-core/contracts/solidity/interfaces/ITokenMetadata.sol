// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ITokenMetadata (industrial aggregate)
/// @notice Унифицированный доступ к метаданным токенов, собранный из стандартизованных EIP:
/// - ERC-165 (детекция интерфейсов)
/// - ERC-20 optional metadata (name/symbol/decimals)
/// - ERC-721 Metadata (tokenURI) + ERC-4906 (MetadataUpdate события)
/// - ERC-1155 Metadata URI (uri)
/// - ERC-7572 contractURI (метаданные на уровне контракта)
/// Сигнатуры полностью соответствуют EIP. Контракты могут реализовывать поднаборы интерфейсов и/или заявлять поддержку агрегата через ERC-165.
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/// ERC-20 optional metadata (EIP-20).
/// name/symbol/decimals исторически объявлены как опциональные расширения к базовому ERC-20.
interface IERC20Metadata /* is ERC-20 metadata extension */ {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

/// ERC-721 Metadata (EIP-721) — стандартные name/symbol/ tokenURI.
interface IERC721Metadata /* is ERC-721 Metadata */ {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
}

/// ERC-1155 Metadata URI (EIP-1155) — единая схема uri(id).
interface IERC1155MetadataURI /* is ERC-1155 Metadata URI */ {
    function uri(uint256 id) external view returns (string memory);
}

/// ERC-4906 — стандартные события обновления метаданных для ERC-721.
/// Контракты МОГУТ эмитить эти события при изменении метаданных токенов/диапазонов.
interface IERC4906 /* Metadata update events */ {
    /// @dev MUST be emitted when the metadata of a token is changed.
    event MetadataUpdate(uint256 _tokenId);
    /// @dev MUST be emitted when the metadata of a range of tokens is changed.
    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);
}

/// ERC-7572 — контрактный уровень метаданных через contractURI() + событие обновления.
interface IERC7572 /* Contract-level metadata */ {
    /// @dev SHOULD return a URI (HTTP(S)/IPFS/Arweave/etc.) с JSON метаданными контракта.
    function contractURI() external view returns (string memory);
    /// @dev SHOULD be emitted при обновлении contractURI.
    event ContractURIUpdated();
}

/// @notice Агрегирующий интерфейс метаданных.
/// @dev Контракты, реализующие ПОЛНЫЙ набор, могут заявить поддержку этого интерфейса через ERC-165.
/// В противном случае заявляйте поддержку соответствующих подинтерфейсов.
interface ITokenMetadata is
    IERC165,
    IERC20Metadata,
    IERC721Metadata,
    IERC1155MetadataURI,
    IERC7572,
    IERC4906
{}
