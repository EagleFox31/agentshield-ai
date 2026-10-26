// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice OPTIONAL, UNDEPLOYED reference for future EVM-testnet review.
/// @dev Anchors only a 32-byte precommitted audit-batch digest. This does NOT
///      prove original event truth/completeness or chain finality.
contract AuditRootRegistry {
    address public owner;
    address public publisher;
    mapping(bytes32 => bool) public anchored;

    event RootAnchored(bytes32 indexed commitment);
    event PublisherUpdated(address indexed previousPublisher, address indexed nextPublisher);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    error NotOwner();
    error NotPublisher();
    error InvalidAddress();
    error EmptyCommitment();
    error AlreadyAnchored();

    constructor(address initialPublisher) {
        if (initialPublisher == address(0)) revert InvalidAddress();
        owner = msg.sender;
        publisher = initialPublisher;
    }

    function setPublisher(address nextPublisher) external {
        if (msg.sender != owner) revert NotOwner();
        if (nextPublisher == address(0)) revert InvalidAddress();
        emit PublisherUpdated(publisher, nextPublisher);
        publisher = nextPublisher;
    }

    function transferOwnership(address nextOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (nextOwner == address(0)) revert InvalidAddress();
        emit OwnershipTransferred(owner, nextOwner);
        owner = nextOwner;
    }

    function anchorRoot(bytes32 commitment) external {
        if (msg.sender != publisher) revert NotPublisher();
        if (commitment == bytes32(0)) revert EmptyCommitment();
        if (anchored[commitment]) revert AlreadyAnchored();
        anchored[commitment] = true;
        emit RootAnchored(commitment);
    }
}
