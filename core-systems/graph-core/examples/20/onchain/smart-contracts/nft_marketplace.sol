// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NFT Marketplace — безопасная и оптимизированная торговая площадка для ERC721 токенов
/// @author Влад
/// @notice Контракт позволяет выставлять NFT на продажу, покупать и снимать с продажи

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract NFTMarketplace is ReentrancyGuard, Ownable {
    struct Listing {
        address seller;
        uint256 price;
    }

    // nftContract => tokenId => Listing
    mapping(address => mapping(uint256 => Listing)) private listings;

    event ItemListed(address indexed seller, address indexed nftContract, uint256 indexed tokenId, uint256 price);
    event ItemCanceled(address indexed seller, address indexed nftContract, uint256 indexed tokenId);
    event ItemBought(address indexed buyer, address indexed nftContract, uint256 indexed tokenId, uint256 price);

    /// @notice Выставить NFT на продажу
    /// @param nftContract адрес контракта NFT
    /// @param tokenId идентификатор токена
    /// @param price цена в wei
    function listItem(address nftContract, uint256 tokenId, uint256 price) external nonReentrant {
        require(price > 0, "Price must be greater than zero");
        IERC721 nft = IERC721(nftContract);
        require(nft.ownerOf(tokenId) == msg.sender, "Not the owner");
        require(nft.getApproved(tokenId) == address(this) || nft.isApprovedForAll(msg.sender, address(this)),
            "Marketplace not approved");

        listings[nftContract][tokenId] = Listing(msg.sender, price);
        emit ItemListed(msg.sender, nftContract, tokenId, price);
    }

    /// @notice Отменить продажу NFT
    /// @param nftContract адрес контракта NFT
    /// @param tokenId идентификатор токена
    function cancelListing(address nftContract, uint256 tokenId) external nonReentrant {
        Listing memory listedItem = listings[nftContract][tokenId];
        require(listedItem.seller == msg.sender, "Not the seller");
        delete listings[nftContract][tokenId];
        emit ItemCanceled(msg.sender, nftContract, tokenId);
    }

    /// @notice Купить выставленный NFT
    /// @param nftContract адрес контракта NFT
    /// @param tokenId идентификатор токена
    function buyItem(address nftContract, uint256 tokenId) external payable nonReentrant {
        Listing memory listedItem = listings[nftContract][tokenId];
        require(listedItem.price > 0, "Item not listed");
        require(msg.value >= listedItem.price, "Insufficient funds");

        // Удаляем листинг до перевода, чтобы избежать повторных вызовов
        delete listings[nftContract][tokenId];

        // Перевод средств продавцу
        (bool success, ) = payable(listedItem.seller).call{value: listedItem.price}("");
        require(success, "Payment to seller failed");

        // Перевод NFT покупателю
        IERC721(nftContract).safeTransferFrom(listedItem.seller, msg.sender, tokenId);

        // Возврат излишков, если есть
        if (msg.value > listedItem.price) {
            (bool refundSuccess, ) = payable(msg.sender).call{value: msg.value - listedItem.price}("");
            require(refundSuccess, "Refund failed");
        }

        emit ItemBought(msg.sender, nftContract, tokenId, listedItem.price);
    }

    /// @notice Получить данные о листинге NFT
    /// @param nftContract адрес контракта NFT
    /// @param tokenId идентификатор токена
    /// @return seller адрес продавца
    /// @return price цена в wei
    function getListing(address nftContract, uint256 tokenId) external view returns (address seller, uint256 price) {
        Listing memory listedItem = listings[nftContract][tokenId];
        return (listedItem.seller, listedItem.price);
    }

    /// @notice Вывод ETH с контракта владельцем (на случай случайных депозитов)
    /// @param amount количество wei для вывода
    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "Not enough balance");
        payable(owner()).transfer(amount);
    }
}
