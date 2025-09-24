// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

interface IReputationEngine {
    function getReputation(address user) external view returns (uint256);
}

interface IParticipationTracker {
    function getParticipationScore(address user) external view returns (uint256);
}

interface INFTWeightOracle {
    function getNFTWeight(address user) external view returns (uint256);
}

contract DAOVotingPower is AccessControl {
    using SafeCast for uint256;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    IERC20 public neuroToken;
    IReputationEngine public reputationEngine;
    IParticipationTracker public participationTracker;
    INFTWeightOracle public nftWeightOracle;

    struct WeightConfig {
        uint16 tokenWeight;        // e.g. 1000 = 100%
        uint16 reputationWeight;   // e.g. 500 = 50%
        uint16 activityWeight;     // e.g. 250 = 25%
        uint16 nftWeight;          // e.g. 200 = 20%
    }

    WeightConfig public weights;

    constructor(
        address _token,
        address _reputation,
        address _participation,
        address _nftOracle
    ) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);

        neuroToken = IERC20(_token);
        reputationEngine = IReputationEngine(_reputation);
        participationTracker = IParticipationTracker(_participation);
        nftWeightOracle = INFTWeightOracle(_nftOracle);

        weights = WeightConfig({
            tokenWeight: 1000,
            reputationWeight: 500,
            activityWeight: 250,
            nftWeight: 250
        });
    }

    function calculateVotingPower(address user) public view returns (uint256) {
        uint256 tokenBalance = neuroToken.balanceOf(user);
        uint256 repScore = reputationEngine.getReputation(user);
        uint256 activityScore = participationTracker.getParticipationScore(user);
        uint256 nftScore = nftWeightOracle.getNFTWeight(user);

        uint256 weightedPower =
            (tokenBalance * weights.tokenWeight) / 1000 +
            (repScore * weights.reputationWeight) / 1000 +
            (activityScore * weights.activityWeight) / 1000 +
            (nftScore * weights.nftWeight) / 1000;

        return weightedPower;
    }

    function setWeights(
        uint16 _token,
        uint16 _reputation,
        uint16 _activity,
        uint16 _nft
    ) external onlyRole(ADMIN_ROLE) {
        require(_token + _reputation + _activity + _nft <= 4000, "Too much weight");
        weights = WeightConfig(_token, _reputation, _activity, _nft);
    }

    function updateSources(
        address _reputation,
        address _participation,
        address _nft
    ) external onlyRole(ADMIN_ROLE) {
        reputationEngine = IReputationEngine(_reputation);
        participationTracker = IParticipationTracker(_participation);
        nftWeightOracle = INFTWeightOracle(_nft);
    }

    function getWeights() external view returns (WeightConfig memory) {
        return weights;
    }
}
