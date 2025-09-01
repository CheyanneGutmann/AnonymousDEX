// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@fhevm/solidity/lib/FHE.sol";
import {SepoliaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title AnonymousDEX - Privacy-First Decentralized Exchange
 * @dev A fully private DEX using Zama's FHE for encrypted order matching
 * @author ZeroFund Team
 */
contract AnonymousDEX is SepoliaConfig, ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    enum OrderType { Buy, Sell }
    enum OrderStatus { Active, PartiallyFilled, Filled, Cancelled }

    struct TradingPair {
        address baseToken;
        address quoteToken;
        bool isActive;
        uint256 totalVolume;
        uint256 lastPrice;
        uint256 priceDecimals;
    }

    struct EncryptedOrder {
        uint256 orderId;
        address trader;
        uint256 pairId;
        OrderType orderType;
        euint64 encryptedAmount;
        euint64 encryptedPrice;
        euint64 encryptedFilled;
        OrderStatus status;
        uint256 timestamp;
        bool isDecrypted;
    }

    struct DecryptedOrderInfo {
        uint256 amount;
        uint256 price;
        uint256 filled;
    }

    // State variables
    mapping(uint256 => TradingPair) public tradingPairs;
    mapping(uint256 => EncryptedOrder) public orders;
    mapping(uint256 => DecryptedOrderInfo) public decryptedOrders;
    mapping(address => uint256[]) public userOrders;
    mapping(uint256 => uint256[]) public pairOrders;
    mapping(address => mapping(address => euint64)) private encryptedBalances;
    
    uint256 public nextPairId = 1;
    uint256 public nextOrderId = 1;
    uint256 public tradingFeeRate = 25; // 0.25%
    uint256 public constant MAX_FEE_RATE = 1000; // 10%
    address public feeCollector;
    
    // Events
    event TradingPairCreated(
        uint256 indexed pairId,
        address indexed baseToken,
        address indexed quoteToken
    );

    event EncryptedOrderPlaced(
        uint256 indexed orderId,
        uint256 indexed pairId,
        address indexed trader,
        OrderType orderType,
        uint256 timestamp
    );

    event OrderMatched(
        uint256 indexed buyOrderId,
        uint256 indexed sellOrderId,
        uint256 matchedAmount,
        uint256 price
    );

    event OrderCancelled(
        uint256 indexed orderId,
        address indexed trader
    );

    event BalanceDeposited(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    event BalanceWithdrawn(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    // Modifiers
    modifier validPair(uint256 _pairId) {
        require(_pairId > 0 && _pairId < nextPairId, "Invalid trading pair");
        require(tradingPairs[_pairId].isActive, "Trading pair inactive");
        _;
    }

    modifier validOrder(uint256 _orderId) {
        require(_orderId > 0 && _orderId < nextOrderId, "Invalid order");
        require(orders[_orderId].trader != address(0), "Order does not exist");
        _;
    }

    modifier onlyOrderOwner(uint256 _orderId) {
        require(orders[_orderId].trader == msg.sender, "Not order owner");
        _;
    }

    constructor(address _feeCollector) Ownable(msg.sender) {
        require(_feeCollector != address(0), "Invalid fee collector");
        feeCollector = _feeCollector;
        
        // Create ETH/USDC pair as default
        _createTradingPair(address(0), address(0x1234567890123456789012345678901234567890)); // Mock addresses for demo
    }

    /**
     * @dev Create a new trading pair
     */
    function createTradingPair(
        address _baseToken,
        address _quoteToken,
        uint256 _priceDecimals
    ) external onlyOwner returns (uint256) {
        require(_baseToken != _quoteToken, "Identical tokens");
        require(_baseToken != address(0) || _quoteToken != address(0), "Both tokens cannot be zero");
        require(_priceDecimals > 0 && _priceDecimals <= 18, "Invalid price decimals");

        return _createTradingPair(_baseToken, _quoteToken);
    }

    function _createTradingPair(address _baseToken, address _quoteToken) internal returns (uint256) {
        uint256 pairId = nextPairId++;
        
        tradingPairs[pairId] = TradingPair({
            baseToken: _baseToken,
            quoteToken: _quoteToken,
            isActive: true,
            totalVolume: 0,
            lastPrice: 0,
            priceDecimals: 18
        });

        emit TradingPairCreated(pairId, _baseToken, _quoteToken);
        return pairId;
    }

    /**
     * @dev Deposit tokens for trading (encrypted balance)
     */
    function depositEncrypted(
        address _token,
        externalEuint64 _encryptedAmount,
        bytes calldata _inputProof
    ) external payable nonReentrant {
        euint64 amount = FHE.fromExternal(_encryptedAmount, _inputProof);
        
        if (_token == address(0)) {
            // ETH deposit
            euint64 ethAmount = FHE.asEuint64(msg.value);
            ebool isValidAmount = FHE.eq(amount, ethAmount);
            require(FHE.decrypt(isValidAmount), "Invalid encrypted ETH amount");
        } else {
            // ERC20 deposit - simplified verification
            uint256 actualAmount = FHE.decrypt(amount);
            IERC20(_token).safeTransferFrom(msg.sender, address(this), actualAmount);
        }

        // Update encrypted balance
        if (address(encryptedBalances[msg.sender][_token]) == address(0)) {
            encryptedBalances[msg.sender][_token] = amount;
        } else {
            encryptedBalances[msg.sender][_token] = FHE.add(encryptedBalances[msg.sender][_token], amount);
        }
        
        FHE.allowThis(encryptedBalances[msg.sender][_token]);
        
        emit BalanceDeposited(msg.sender, _token, FHE.decrypt(amount));
    }

    /**
     * @dev Place an encrypted order
     */
    function placeEncryptedOrder(
        uint256 _pairId,
        OrderType _orderType,
        externalEuint64 _encryptedAmount,
        externalEuint64 _encryptedPrice,
        bytes calldata _amountProof,
        bytes calldata _priceProof
    ) external nonReentrant validPair(_pairId) returns (uint256) {
        euint64 amount = FHE.fromExternal(_encryptedAmount, _amountProof);
        euint64 price = FHE.fromExternal(_encryptedPrice, _priceProof);
        
        TradingPair storage pair = tradingPairs[_pairId];
        address requiredToken = _orderType == OrderType.Buy ? pair.quoteToken : pair.baseToken;
        
        // Verify user has sufficient encrypted balance
        ebool hasBalance = FHE.gte(encryptedBalances[msg.sender][requiredToken], amount);
        require(FHE.decrypt(hasBalance), "Insufficient balance");

        uint256 orderId = nextOrderId++;
        
        orders[orderId] = EncryptedOrder({
            orderId: orderId,
            trader: msg.sender,
            pairId: _pairId,
            orderType: _orderType,
            encryptedAmount: amount,
            encryptedPrice: price,
            encryptedFilled: FHE.asEuint64(0),
            status: OrderStatus.Active,
            timestamp: block.timestamp,
            isDecrypted: false
        });

        // Allow contract to work with encrypted values
        FHE.allowThis(amount);
        FHE.allowThis(price);
        FHE.allowThis(orders[orderId].encryptedFilled);

        userOrders[msg.sender].push(orderId);
        pairOrders[_pairId].push(orderId);

        // Reserve funds by reducing balance
        encryptedBalances[msg.sender][requiredToken] = FHE.sub(
            encryptedBalances[msg.sender][requiredToken], 
            amount
        );
        FHE.allowThis(encryptedBalances[msg.sender][requiredToken]);

        emit EncryptedOrderPlaced(orderId, _pairId, msg.sender, _orderType, block.timestamp);
        
        // Attempt to match orders
        _attemptOrderMatching(_pairId, orderId);
        
        return orderId;
    }

    /**
     * @dev Attempt to match orders (simplified matching logic)
     */
    function _attemptOrderMatching(uint256 _pairId, uint256 _newOrderId) internal {
        EncryptedOrder storage newOrder = orders[_newOrderId];
        uint256[] storage pairOrderList = pairOrders[_pairId];
        
        for (uint256 i = 0; i < pairOrderList.length; i++) {
            uint256 existingOrderId = pairOrderList[i];
            if (existingOrderId == _newOrderId) continue;
            
            EncryptedOrder storage existingOrder = orders[existingOrderId];
            
            // Only match opposite order types
            if (existingOrder.orderType == newOrder.orderType) continue;
            if (existingOrder.status != OrderStatus.Active) continue;
            
            // In a full implementation, we would use FHE comparisons
            // For now, we'll use a simplified matching approach
            _executeMatch(_newOrderId, existingOrderId);
            break; // Simplified: only match with first compatible order
        }
    }

    /**
     * @dev Execute order match (simplified)
     */
    function _executeMatch(uint256 _buyOrderId, uint256 _sellOrderId) internal {
        // In production, this would involve complex FHE computations
        // For demo purposes, we'll emit the match event
        emit OrderMatched(_buyOrderId, _sellOrderId, 0, 0);
    }

    /**
     * @dev Cancel an order
     */
    function cancelOrder(uint256 _orderId) 
        external 
        nonReentrant 
        validOrder(_orderId) 
        onlyOrderOwner(_orderId) 
    {
        EncryptedOrder storage order = orders[_orderId];
        require(order.status == OrderStatus.Active, "Order not active");
        
        order.status = OrderStatus.Cancelled;
        
        // Refund unused amount to encrypted balance
        TradingPair storage pair = tradingPairs[order.pairId];
        address refundToken = order.orderType == OrderType.Buy ? pair.quoteToken : pair.baseToken;
        
        euint64 unfilledAmount = FHE.sub(order.encryptedAmount, order.encryptedFilled);
        encryptedBalances[msg.sender][refundToken] = FHE.add(
            encryptedBalances[msg.sender][refundToken],
            unfilledAmount
        );
        FHE.allowThis(encryptedBalances[msg.sender][refundToken]);
        
        emit OrderCancelled(_orderId, msg.sender);
    }

    /**
     * @dev Withdraw encrypted balance
     */
    function withdrawEncrypted(address _token, externalEuint64 _encryptedAmount, bytes calldata _inputProof) 
        external 
        nonReentrant 
    {
        euint64 amount = FHE.fromExternal(_encryptedAmount, _inputProof);
        
        // Verify sufficient balance
        ebool hasBalance = FHE.gte(encryptedBalances[msg.sender][_token], amount);
        require(FHE.decrypt(hasBalance), "Insufficient balance");
        
        // Update balance
        encryptedBalances[msg.sender][_token] = FHE.sub(encryptedBalances[msg.sender][_token], amount);
        FHE.allowThis(encryptedBalances[msg.sender][_token]);
        
        uint256 withdrawAmount = FHE.decrypt(amount);
        
        if (_token == address(0)) {
            payable(msg.sender).transfer(withdrawAmount);
        } else {
            IERC20(_token).safeTransfer(msg.sender, withdrawAmount);
        }
        
        emit BalanceWithdrawn(msg.sender, _token, withdrawAmount);
    }

    /**
     * @dev Request decryption of user's balance for a specific token
     */
    function requestBalanceDecryption(address _token) external {
        require(address(encryptedBalances[msg.sender][_token]) != address(0), "No balance found");
        
        bytes32[] memory cts = new bytes32[](1);
        cts[0] = FHE.toBytes32(encryptedBalances[msg.sender][_token]);
        uint256 requestId = FHE.requestDecryption(cts, this.callbackDecryptBalance.selector);
        
        // In production, you'd store the mapping of requestId to user and token
    }

    /**
     * @dev Callback for balance decryption
     */
    function callbackDecryptBalance(
        uint256 requestId,
        uint64 decryptedBalance,
        bytes[] memory signatures
    ) public {
        FHE.checkSignatures(requestId, signatures);
        // Handle decrypted balance (emit event, update storage, etc.)
    }

    // View functions
    function getTradingPair(uint256 _pairId) external view returns (TradingPair memory) {
        return tradingPairs[_pairId];
    }

    function getOrder(uint256 _orderId) external view returns (EncryptedOrder memory) {
        return orders[_orderId];
    }

    function getUserOrders(address _user) external view returns (uint256[] memory) {
        return userOrders[_user];
    }

    function getPairOrders(uint256 _pairId) external view returns (uint256[] memory) {
        return pairOrders[_pairId];
    }

    function getActivePairs() external view returns (uint256[] memory) {
        uint256 count = 0;
        for (uint256 i = 1; i < nextPairId; i++) {
            if (tradingPairs[i].isActive) {
                count++;
            }
        }
        
        uint256[] memory activePairs = new uint256[](count);
        uint256 index = 0;
        
        for (uint256 i = 1; i < nextPairId; i++) {
            if (tradingPairs[i].isActive) {
                activePairs[index] = i;
                index++;
            }
        }
        
        return activePairs;
    }

    // Admin functions
    function updateTradingFee(uint256 _newFeeRate) external onlyOwner {
        require(_newFeeRate <= MAX_FEE_RATE, "Fee rate too high");
        tradingFeeRate = _newFeeRate;
    }

    function updateFeeCollector(address _newFeeCollector) external onlyOwner {
        require(_newFeeCollector != address(0), "Invalid fee collector");
        feeCollector = _newFeeCollector;
    }

    function togglePair(uint256 _pairId) external onlyOwner validPair(_pairId) {
        tradingPairs[_pairId].isActive = !tradingPairs[_pairId].isActive;
    }
}